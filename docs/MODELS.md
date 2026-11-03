# Models

## The rule that comes first

**A model in Soc Thief is advisory only. It can never suppress, hide, delay or downgrade an
alert.** Every group a model reviews is still delivered, whatever the model says. If the model is
down, slow or returns something invalid, the group is delivered anyway with a health failure. Your
tuning file is the only thing that suppresses alerts. See [POLICY.md](POLICY.md#the-model-cannot-suppress)
for the measurement behind this rule.

So choosing a model changes how your digest is ordered and annotated. It does not change what you
are shown.

## Pick your backend

| Backend | Where data goes | Status |
| --- | --- | --- |
| Local Ollama (default, `qwen3:4b`) | Stays on the host, over loopback | The default and the most tested |
| OpenAI-compatible chat API | Loopback by default; a remote endpoint only if you opt in | Being added for the first release |
| Jev over the System One API | A hosted preset leaves the host, pseudonymised; a local server stays on loopback | Experimental, opt-in, never run as the live default |

### The privacy trade-off

A local model sees alert group summaries and nothing leaves the machine. A hosted model sees
pseudonymised summaries, and they leave your network every day. Pseudonymisation replaces host
names with tokens and masks IP addresses, URLs and obvious secrets, but rule descriptions, decoder
names and log locations still go out, and they can say a lot about your environment. Decide
whether that is acceptable before you point Soc Thief at a remote endpoint. If in doubt, stay
local.

## Local Ollama (default)

The default adapter is `OllamaTriage` in `src/soc_thief/model.py`. Install
[Ollama](https://ollama.com) on the same host and pull the model:

```sh
ollama pull qwen3:4b
```

Settings (plain values, not secrets):

| Setting | Default | Meaning |
| --- | --- | --- |
| `MODEL_BASE_URL` | `http://127.0.0.1:11434` | Must be a bare loopback HTTP origin (IPv4 or IPv6). Anything else is refused. |
| `MODEL_NAME` | `qwen3:4b` | Any model your Ollama has pulled |
| `MODEL_TIMEOUT_SECONDS` | `60` | 1 to 120 |

How it calls the model:

- Preflight runs first. Protected, critical, breach and tuned groups never reach the model.
- One non-streaming `/api/chat` request per group, temperature 0, thinking disabled, a fixed JSON
  schema, proxies ignored, redirects refused.
- The group goes in its own user message as data, under a fixed system instruction, so alert text
  cannot rewrite the prompt.
- The answer must be exactly `classification`, `confidence`, `rationale` and `analyst_action`.
  Duplicate keys, non-finite numbers and malformed envelopes are rejected.
- Only the model's reported identity (for example `qwen3:4b`) is stored, on the audit row. The
  prompt, response, rationale and endpoint are never stored or rendered.

In the systemd units, the container reaches the host's Ollama through rootless Podman's `pasta`
port forwarding (`SOC_THIEF_MODEL_PORT`), so no external network access is needed.

### What we know about qwen3:4b

It is small enough for a home server and fast enough for a daily window. It does not give a usable
confidence: in measurement it reported only 0.95 or 0.85, and the same group could flip between
benign and suspicious across identical requests at temperature 0. Treat its classification as a
hint for ordering, not a verdict.

## OpenAI-compatible chat API

This backend speaks the OpenAI chat-completions format. That covers local servers such as
Ollama, LM Studio, llama.cpp's server and vLLM, and hosted APIs such as OpenRouter. It asks for
a strict JSON schema in the response, so the server or model must support structured output.

| Setting | Value |
| --- | --- |
| `SOC_THIEF_MODEL_BACKEND` | `openai` (the default is `ollama`) |
| `SOC_THIEF_OPENAI_BASE_URL` | The API base, for example `http://127.0.0.1:1234/v1` or `https://openrouter.ai/api/v1` |
| `SOC_THIEF_OPENAI_MODEL` | The model name the server expects |
| `SOC_THIEF_OPENAI_API_KEY_FILE` | Path to a file holding the key, if the server needs one |
| `SOC_THIEF_OPENAI_TIMEOUT_SECONDS` | 1 to 120, default 60 |
| `SOC_THIEF_OPENAI_ALLOW_REMOTE` | `1` to allow an endpoint that isn't on this machine |

Keys are only read from a file. Never from a plain environment variable or a flag.

Plain `http` is only allowed to a loopback IP address such as `127.0.0.1`. Anything else needs
`https` and `SOC_THIEF_OPENAI_ALLOW_REMOTE=1`. Even `localhost` counts as remote, because a name
can resolve somewhere you didn't expect. Setting that opt-in is your decision that alert
summaries may leave the host. What's sent is the rule ID, level, event count, decoder and the
rule description. In the description, the group's agent and manager names are replaced with
`[host]`, and addresses, URLs and secret-looking values are masked. Agent IDs, timestamps and
locations are not sent. Some Wazuh rules put event text into their description, so other
details, such as a user name, can still get through. Read a few of your own descriptions before
you turn a remote model on.

A hosted example, using OpenRouter:

```sh
SOC_THIEF_MODEL_BACKEND=openai
SOC_THIEF_OPENAI_BASE_URL=https://openrouter.ai/api/v1
SOC_THIEF_OPENAI_MODEL=<a model that supports structured output>
SOC_THIEF_OPENAI_API_KEY_FILE=/run/secrets/openai_key
SOC_THIEF_OPENAI_ALLOW_REMOTE=1
```
- Host egress: a remote endpoint also needs a rule in your host egress policy for that one
  destination. See [DEPLOYMENT.md](DEPLOYMENT.md#egress-policy).

The same rules apply as for Ollama: strict JSON answer, one request per group, failures deliver
with a health failure, and the answer cannot suppress anything.

### In the systemd units

The units use Ollama unless you add a drop-in. Two ship in `deploy/systemd/`:

- `soc-thief-runner-openai.conf`, installed as
  `/etc/systemd/system/soc-thief-runner.service.d/openai.conf`;
- `soc-thief-reconcile-openai.conf`, installed as
  `/etc/systemd/system/soc-thief-reconcile.service.d/openai.conf`.

Install both, so the daily run and the late-alert pass use the same model. Each one selects the
backend, passes the settings above, loads the key as a credential and changes which host
loopback port the container can reach. Nothing else changes. Do not combine the runner drop-in
with the Jev one, because both replace the same command.

1. Save the key in `/etc/soc-thief/secrets/openai_key`, root-owned, mode `0600`. The drop-in
   always loads it, and the unit fails to start without it. If your server takes no key, write
   any placeholder such as `none`; it is sent as a bearer token and ignored.
2. Add the settings to `/etc/soc-thief/environment`. For a server on host loopback:

   ```
   SOC_THIEF_OPENAI_BASE_URL=http://127.0.0.1:1234/v1
   SOC_THIEF_OPENAI_MODEL=qwen3-4b
   SOC_THIEF_OPENAI_PORT=1234
   ```

   `SOC_THIEF_OPENAI_PORT` is the port forwarded into the container, in place of
   `SOC_THIEF_MODEL_PORT`. It must match the port in the base URL. For a remote endpoint, use an
   `https` base URL, add `SOC_THIEF_OPENAI_ALLOW_REMOTE=1`, and set `SOC_THIEF_OPENAI_PORT` to the
   same value as `SOC_THIEF_MODEL_PORT`. Nothing uses that port then; it only keeps the container's
   loopback access the same as before. `SOC_THIEF_OPENAI_TIMEOUT_SECONDS` is optional.
3. A remote endpoint also needs an HTTPS rule for that one destination in your egress policy, see
   [DEPLOYMENT.md](DEPLOYMENT.md#egress-policy). A loopback server needs none.
4. `sudo systemctl daemon-reload`.

Remove the drop-ins and reload to go back to Ollama.

Two units stay on Ollama. The backfill always uses the Ollama adapter, so a drop-in would change
nothing there. The fast path's follow-up has its own model setting, a 30 second budget inside the
unit's timeout and runs on every breach page, so it is left on its local model.

## Jev (experimental)

TypeSafe's Jev is a model that returns typed judgements and probabilities rather than chat text.
It is served over TypeSafe's [System One API](https://docs.typesafe.ai/api/system-one). System One
is a protocol, not one service. TypeSafe and OpenRouter host it, and other providers and local
servers implement it too. Soc Thief works with any System One-compatible server. Soc Thief can
ask it two things about each group:

- an attention score: the probability that the group warrants an analyst's attention;
- a threat tag from a fixed list: `routine`, `possible_auth_abuse`, `possible_malware`,
  `possible_privilege_misuse`, `possible_policy_violation`, `other_concern`,
  `insufficient_context`.

Both are used only to order groups within a severity level and to show in the digest and the
attachment. They never enter `policy.decide()` or tuning. An unknown or malformed answer fails
closed for that group with a health failure.

### What the evidence says

- In one measurement on real alert groups, Jev's score separated groups within the same severity
  level, where the chat models did not.
- A later comparison used 40 groups labelled by investigating each one in the logs. Every one of
  the 40 turned out to be routine, so the comparison could not rank the models. Accuracy on real
  findings is unmeasured.
- Jev has not been run as the live default anywhere. Treat it as an experiment.

### Turning it on

Pick a route in `/etc/soc-thief/environment`. Use a preset, or give the base URL of any
System One server.

| `SOC_THIEF_JEV_ENDPOINT` | Where requests go | Key | Default model |
| --- | --- | --- | --- |
| `typesafe` (default) | TypeSafe's own API, `api.typesafe.ai` | TypeSafe | `jev-latest` |
| `openrouter` | OpenRouter, `openrouter.ai` | OpenRouter | `typesafe/jev-1.13` |
| `vercel` | The older Vercel AI Gateway route | Vercel AI Gateway | `typesafe-ai/jev` |

The `typesafe` and `openrouter` presets fill in a base URL and a default model. Soc Thief handles
them like any other System One server. In the owner's testing, OpenRouter was refused for rate
limits far less often than Vercel. `vercel` uses an older request shape and is kept for
deployments that already use it. Set `SOC_THIEF_JEV_MODEL` to pin a different model.

For any other System One server, leave `SOC_THIEF_JEV_ENDPOINT` empty and set:

| Setting | Value |
| --- | --- |
| `SOC_THIEF_JEV_BASE_URL` | The API base. Soc Thief calls it with `/systemone` added, for example `http://127.0.0.1:8080/v1` becomes `http://127.0.0.1:8080/v1/systemone` |
| `SOC_THIEF_JEV_MODEL` | Required. The model name the server expects |
| `SOC_THIEF_JEV_KEY_FILE` | Path to a file holding the key. Optional for a loopback server only |
| `SOC_THIEF_JEV_ALLOW_REMOTE` | `1` to allow a server that isn't on this machine |

The URL rules are the same as for the OpenAI-compatible backend. Plain `http` is only allowed to a
loopback IP address such as `127.0.0.1`. Anything else needs `https` and
`SOC_THIEF_JEV_ALLOW_REMOTE=1`. `localhost` counts as remote. Setting both a preset and a base URL
is refused. Choosing a hosted preset is itself your decision that data leaves the host, so the
presets do not need `SOC_THIEF_JEV_ALLOW_REMOTE`.

1. Save the key in a root-owned `0600` file, `/etc/soc-thief/secrets/jev_key`. The drop-in always
   loads it. A local server without keys accepts any placeholder value.
2. Install the drop-in `deploy/systemd/soc-thief-runner-jev-trial.conf` as
   `/etc/systemd/system/soc-thief-runner.service.d/jev-trial.conf`. It loads the key as a
   credential and turns Jev on for the daily runner. It passes the settings above through from the
   environment file. The container can reach only one host loopback port for a model,
   `SOC_THIEF_MODEL_PORT`, so a local System One server must listen there.
3. For a remote server, allow HTTPS egress to its host for the service account.
   `python -m soc_thief.jev_egress --endpoint <preset> --source <your nft policy file> --output <new file>`,
   or `--base-url <url>` in place of `--endpoint`, writes a proposed policy with one narrowly
   scoped rule inserted before the drop rule. It never applies anything; review it and load it
   yourself. A loopback server needs no rule. The policy file itself is described in
   [DEPLOYMENT.md](DEPLOYMENT.md).
4. `systemctl daemon-reload`.

Remove the drop-in and reload to switch back to the local model.

If you set up Jev before the `typesafe` route existed, your key is a Vercel key. Add
`SOC_THIEF_JEV_ENDPOINT=vercel` to the environment file, or the next run will send it to the
wrong place and every Jev review will fail closed.

What Jev receives: capped group summaries only. Before any request, host and manager names for the
whole window are replaced with tokens such as `host-01`, and IP addresses, URLs and secret-looking
values are masked. Only the operator's settings choose the route. Alert data cannot change the
route or the model. A deadline and a repeated-failure cut-off leave the runner time to finish its report
if Jev is slow or down. Any HTTP error, redirect, timeout or malformed answer fails closed for
that group. The error body is never logged.

`soc_thief.jev_evaluation` and `soc_thief.model_comparison` compare model output against a private
worksheet of labelled groups, if you want to run your own comparison.

## Follow-up investigation model

The fast path's optional follow-up uses the local Ollama adapter with a different, closed schema.
See [INVESTIGATION.md](INVESTIGATION.md#automatic-follow-up-on-a-breach-page).
