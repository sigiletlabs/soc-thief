//! Local, read-only web dashboard. Loopback only, GET only, no outbound network.

use crate::snapshot::{Snapshot, sanitize};
use crate::source::{Freshness, POLL_INTERVAL, SnapshotSource};
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_CSS: &str = include_str!("../assets/app.css");
const APP_JS: &str = include_str!("../assets/app.js");

pub const CSP: &str =
    "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// Refuse anything that is not a loopback address.
pub fn check_listen(addr: SocketAddr) -> Result<(), String> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(format!(
            "refusing to listen on {addr}: the web view only binds to a loopback address \
             (127.0.0.1 or ::1). It has no authentication and must not be reachable from the network."
        ))
    }
}

/// The Host header values a browser can legitimately send to this listener.
/// Anything else is refused, which stops DNS-rebinding pages from reading the API.
pub fn allowed_hosts(addr: SocketAddr) -> Vec<String> {
    let port = addr.port();
    let ip = match addr {
        SocketAddr::V4(a) => a.ip().to_string(),
        SocketAddr::V6(a) => format!("[{}]", a.ip()),
    };
    let mut hosts = vec![format!("{ip}:{port}"), format!("localhost:{port}")];
    if port == 80 {
        hosts.push(ip);
        hosts.push("localhost".into());
    }
    hosts
}

struct Inner {
    source: SnapshotSource,
    body: Arc<Vec<u8>>,
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<Inner>>,
    hosts: Arc<Vec<String>>,
}

#[derive(Serialize)]
struct ApiBody<'a> {
    state: &'static str,
    error: Option<String>,
    generation: u64,
    file: String,
    snapshot: Option<&'a Snapshot>,
}

fn render_body(source: &SnapshotSource) -> Arc<Vec<u8>> {
    let file = source
        .path()
        .file_name()
        .map(|f| sanitize(&f.to_string_lossy(), 64))
        .unwrap_or_default();
    let body = ApiBody {
        state: match source.freshness() {
            Freshness::Live => "live",
            Freshness::Stale => "stale",
            Freshness::Unavailable => "unavailable",
        },
        error: source.error().map(|e| e.to_string()),
        generation: source.generation(),
        file,
        snapshot: source.snapshot().map(|s| s.as_ref()),
    };
    Arc::new(serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"state\":\"unavailable\"}".to_vec()))
}

impl AppState {
    pub fn new(source: SnapshotSource, listen: SocketAddr) -> Self {
        let body = render_body(&source);
        AppState {
            inner: Arc::new(Mutex::new(Inner { source, body })),
            hosts: Arc::new(allowed_hosts(listen)),
        }
    }

    /// Re-read the snapshot if the file changed.
    pub fn poll(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.source.poll() {
            inner.body = render_body(&inner.source);
        }
    }

    fn body(&self) -> Arc<Vec<u8>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .body
            .clone()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.css", get(css))
        .route("/app.js", get(js))
        .route("/api/snapshot", get(api_snapshot))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state.clone(), host_check))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn index() -> Response {
    asset("text/html; charset=utf-8", INDEX_HTML)
}

async fn css() -> Response {
    asset("text/css; charset=utf-8", APP_CSS)
}

async fn js() -> Response {
    asset("text/javascript; charset=utf-8", APP_JS)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn api_snapshot(State(state): State<AppState>) -> Response {
    let body = state.body();
    (
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(body.as_ref().clone()),
    )
        .into_response()
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

async fn host_check(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| state.hosts.iter().any(|a| a.eq_ignore_ascii_case(h)));
    if !ok {
        return (StatusCode::MISDIRECTED_REQUEST, "unexpected Host header\n").into_response();
    }
    next.run(req).await
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    // Nothing here is worth caching, and the API must always be current.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Serve until Ctrl-C.
pub async fn serve(source: SnapshotSource, listen: SocketAddr) -> std::io::Result<()> {
    check_listen(listen).map_err(std::io::Error::other)?;
    let state = AppState::new(source, listen);
    let poller = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        loop {
            tick.tick().await;
            poller.poll();
        }
    });
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let local = listener.local_addr()?;
    eprintln!(
        "soc-thief-console: serving http://{local}/ (read-only, loopback only). Ctrl-C stops."
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use http_body_util::BodyExt;
    use std::path::PathBuf;
    use tower::ServiceExt;

    const LISTEN: &str = "127.0.0.1:8787";

    fn app() -> Router {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/demo.json");
        router(AppState::new(
            SnapshotSource::new(path),
            LISTEN.parse().unwrap(),
        ))
    }

    fn req(method: Method, uri: &str, host: Option<&str>) -> Request {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(h) = host {
            b = b.header(header::HOST, h);
        }
        b.body(Body::empty()).unwrap()
    }

    async fn get_ok(uri: &str) -> Response {
        app()
            .oneshot(req(Method::GET, uri, Some(LISTEN)))
            .await
            .unwrap()
    }

    fn assert_security_headers(res: &Response) {
        let h = res.headers();
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], CSP);
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn pages_and_api_carry_security_headers() {
        for (uri, ctype) in [
            ("/", "text/html; charset=utf-8"),
            ("/app.css", "text/css; charset=utf-8"),
            ("/app.js", "text/javascript; charset=utf-8"),
            ("/api/snapshot", "application/json"),
        ] {
            let res = get_ok(uri).await;
            assert_eq!(res.status(), StatusCode::OK, "{uri}");
            assert_eq!(res.headers()[header::CONTENT_TYPE], ctype, "{uri}");
            assert_security_headers(&res);
        }
    }

    #[tokio::test]
    async fn api_returns_sanitised_snapshot() {
        let res = get_ok("/api/snapshot").await;
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["state"], "live");
        assert_eq!(v["file"], "demo.json");
        assert_eq!(v["snapshot"]["source"], "demo");
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        // JSON escapes would reintroduce ESC as \u001b; it must not be there at all.
        assert!(!text.contains("\\u001b") && !text.contains('\u{1b}'));
    }

    #[tokio::test]
    async fn wrong_or_missing_host_is_refused() {
        for host in [
            Some("evil.example.com:8787"),
            Some("127.0.0.1:9999"),
            Some("127.0.0.1"),
            None,
        ] {
            let res = app()
                .oneshot(req(Method::GET, "/api/snapshot", host))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::MISDIRECTED_REQUEST, "{host:?}");
            assert_security_headers(&res);
        }
        let res = app()
            .oneshot(req(Method::GET, "/api/snapshot", Some("localhost:8787")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn only_get_is_allowed() {
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let res = app()
                .oneshot(req(m.clone(), "/api/snapshot", Some(LISTEN)))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED, "{m}");
        }
        let res = get_ok("/etc/passwd").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_security_headers(&res);
    }

    #[test]
    fn non_loopback_listen_is_refused() {
        for a in [
            "0.0.0.0:8787",
            "192.0.2.10:8787",
            "[::]:8787",
            "[::ffff:127.0.0.1]:80",
        ] {
            assert!(check_listen(a.parse().unwrap()).is_err(), "{a}");
        }
        for a in ["127.0.0.1:8787", "127.0.0.2:1", "[::1]:8787"] {
            assert!(check_listen(a.parse().unwrap()).is_ok(), "{a}");
        }
    }

    #[test]
    fn page_shows_capped_group_count() {
        assert!(INDEX_HTML.contains("id=\"group-capped\""));
        assert!(APP_JS.contains("\"showing \""));
        assert!(APP_JS.contains("(s.window || {}).groups"));
    }

    #[test]
    fn host_list_for_ipv6() {
        let hosts = allowed_hosts("[::1]:8787".parse().unwrap());
        assert!(hosts.contains(&"[::1]:8787".to_string()));
        assert!(hosts.contains(&"localhost:8787".to_string()));
    }

    #[test]
    fn page_has_no_inline_script_or_style_and_no_innerhtml() {
        assert!(!INDEX_HTML.contains("<script>"));
        assert!(!INDEX_HTML.contains("style="));
        assert!(!INDEX_HTML.contains("<style"));
        assert!(!INDEX_HTML.contains("http://") && !INDEX_HTML.contains("https://"));
        assert!(!APP_CSS.contains("http://") && !APP_CSS.contains("https://"));
        assert!(!APP_CSS.contains("@import") && !APP_CSS.contains("url("));
        for bad in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
        ] {
            assert!(!APP_JS.contains(bad), "{bad} in app.js");
        }
    }
}
