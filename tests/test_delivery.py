"""Synthetic renderer and webhook-client tests; no Discord request is made."""
from soc_thief import __version__
import json, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import Mock, patch
from soc_thief.delivery import MAX_PAGES, DiscordConfig, DiscordDelivery, DeliveryError, RendererError, Report, ReportItem, render
from soc_thief.policy import Decision

GROUP = {"timestamp":"2026-01-01T00:00:00+00:00","rule_id":"100","rule_level":8,"rule_description":"Synthetic alert from 192.0.2.1 with token=private and @everyone","agent_id":"001","count":4}
REQUIRED = Decision(True, False, "model_requires_review")
class Response:
    status, headers = 204, {}
    def getcode(self): return self.status
    def __enter__(self): return self
    def __exit__(self,*args): return False
class DeliveryTest(unittest.TestCase):
    def report(self,*items): return Report(datetime(2026,1,1,tzinfo=timezone.utc),datetime(2026,1,2,tzinfo=timezone.utc),tuple(items),2,0)
    def path(self, root):
        path=Path(root)/"webhook"; path.write_text("https://discord.com/api/webhooks/1234567890123456/abcdefghijklmnopqrstuvwxyz"); path.chmod(0o600); return path
    def test_renderer_masks_escapes_and_disables_mentions(self):
        payload=render(self.report(ReportItem(GROUP,REQUIRED))).payloads[0]; content=payload["content"]
        self.assertEqual(payload["allowed_mentions"],{"parse":[]}); self.assertNotIn("192.0.2.1",content); self.assertNotIn("token=private",content); self.assertNotIn("@everyone",content); self.assertIn("[masked IP]",content)
    def test_renderer_rejects_unknown_suppressed_and_unsafe_input(self):
        for group, decision in [({**GROUP,"raw":"no"},REQUIRED),(GROUP,Decision(False,False,"high_confidence_benign")),({**GROUP,"agent_id":"bad\ntext"},REQUIRED)]:
            with self.assertRaises(RendererError): render(self.report(ReportItem(group,decision)))
    def test_renderer_pages_the_tail_rather_than_dropping_it(self):
        # A real day is 169 groups against a ~10-group message. Groups page 1 cannot show
        # in full belong on a continuation page, not in an omission notice.
        output=render(self.report(*(ReportItem({**GROUP,"rule_id":str(i),"rule_description":"x" * 680},REQUIRED) for i in range(10))))
        self.assertEqual((output.truncated,output.omitted_count),(False,0))
        self.assertGreater(len(output.payloads),1)
        for payload in output.payloads:
            self.assertLessEqual(len(payload["content"]),1900); self.assertEqual(payload["allowed_mentions"],{"parse":[]})
        joined="\n".join(payload["content"] for payload in output.payloads)
        for index in range(10): self.assertIn(f"`{index}`",joined)
        self.assertIn("Remaining",output.payloads[0]["content"]); self.assertNotIn("omitted",joined)

    def test_renderer_counts_the_groups_no_page_can_carry(self):
        items=tuple(ReportItem({**GROUP,"rule_id":str(i),"rule_description":"x" * 680},REQUIRED) for i in range(400))
        output=render(self.report(*items))
        self.assertTrue(output.truncated); self.assertGreater(output.omitted_count,0)
        self.assertEqual(len(output.payloads),MAX_PAGES)
        page=output.payloads[0]["content"]
        self.assertIn(f"[health review] Groups omitted entirely: {output.omitted_count}",page)
        self.assertIn("Delivery-required groups: 400",page)
        # Every group page 1 does not show in full is still counted by severity, omitted or not.
        self.assertIn(f"severity 8: {400 - page.count(chr(8226) + ' Rule')} groups",page)
        for payload in output.payloads: self.assertLessEqual(len(payload["content"]),1900)

    def test_renderer_ranks_by_severity_then_volume(self):
        items=(ReportItem({**GROUP,"rule_id":"bulk","rule_level":3,"count":9000},REQUIRED),
               ReportItem({**GROUP,"rule_id":"small","rule_level":10,"count":2},REQUIRED),
               ReportItem({**GROUP,"rule_id":"large","rule_level":10,"count":5},REQUIRED))
        content=render(self.report(*items)).payloads[0]["content"]
        self.assertLess(content.index("`large`"),content.index("`small`"))
        self.assertLess(content.index("`small`"),content.index("`bulk`"))
    def test_tuning_summary_line_is_fixed_format_and_only_when_nonzero(self):
        start,end=datetime(2026,1,1,tzinfo=timezone.utc),datetime(2026,1,2,tzinfo=timezone.utc)
        content=render(Report(start,end,(ReportItem(GROUP,REQUIRED),),2,0)).payloads[0]["content"]
        self.assertNotIn("Low priority",content); self.assertNotIn("Muted",content)
        content=render(Report(start,end,(ReportItem(GROUP,REQUIRED),),2,0,muted_groups=2,muted_events=40,low_groups=3,low_events=7)).payloads[0]["content"]
        self.assertIn("\nLow priority: 7 events in 3 groups. Muted: 40 events in 2 groups.\n",content)
        self.assertEqual(content.count("Low priority:"),1)
        content=render(Report(start,end,(ReportItem(GROUP,REQUIRED),),0,0,muted_groups=1,muted_events=1)).payloads[0]["content"]
        self.assertIn("Low priority: 0 events in 0 groups. Muted: 1 events in 1 groups.",content)
        big=2**63-1
        output=render(Report(start,end,tuple(ReportItem({**GROUP,"rule_id":str(i),"rule_description":"x"*680},REQUIRED) for i in range(10)),big,big,muted_groups=big,muted_events=big,low_groups=big,low_events=big))
        self.assertIn("Low priority:",output.payloads[0]["content"]); self.assertLessEqual(len(output.payloads[0]["content"]),1900)
        for bad in (dict(muted_groups=-1),dict(muted_events=True),dict(low_groups="1"),dict(low_events=2**63)):
            with self.subTest(bad=bad), self.assertRaises(RendererError): render(Report(start,end,(),0,1,**bad))
    def test_delivery_retries_private_file_config(self):
        with tempfile.TemporaryDirectory() as root:
            opener,sleep=Mock(),Mock(); opener.open.side_effect=[OSError(),Response()]
            client=DiscordDelivery(DiscordConfig(self.path(root),max_attempts=2),opener,sleep); client.send(render(self.report(ReportItem(GROUP,REQUIRED))))
            self.assertEqual(opener.open.call_count,2); self.assertEqual(sleep.call_args.args,(1,)); self.assertLessEqual(len(opener.open.call_args.args[0].data),8*1024)
    def test_webhook_rate_limit_uses_bounded_retry_after(self):
        with tempfile.TemporaryDirectory() as root:
            opener, sleep = Mock(), Mock()
            opener.open.side_effect = [HTTPError("https://example.test", 429, "synthetic",
                                                  {"Retry-After": "2.5"}, None), Response()]
            client = DiscordDelivery(DiscordConfig(self.path(root), max_attempts=2), opener, sleep)
            client.send(render(self.report(ReportItem(GROUP, REQUIRED))))
            self.assertEqual(sleep.call_args.args, (2.5,))
            for invalid in ("nan", "31", "not-a-number"):
                with self.subTest(invalid=invalid):
                    opener.open.side_effect = HTTPError("https://example.test", 429, "synthetic",
                                                        {"Retry-After": invalid}, None)
                    with self.assertRaises(DeliveryError):
                        client.send(render(self.report(ReportItem(GROUP, REQUIRED))))
    def test_every_http_error_is_closed(self):
        # An unclosed HTTPError holds the response body until garbage collection, and its
        # finaliser's ResourceWarning made an unrelated test fail intermittently.
        with tempfile.TemporaryDirectory() as root:
            retried = HTTPError("https://example.test", 503, "synthetic", {}, None)
            final = HTTPError("https://example.test", 400, "synthetic", {}, None)
            opener, sleep = Mock(), Mock()
            opener.open.side_effect = [retried, final]
            client = DiscordDelivery(DiscordConfig(self.path(root), max_attempts=2), opener, sleep)
            with self.assertRaises(DeliveryError):
                client.send(render(self.report(ReportItem(GROUP, REQUIRED))))
            self.assertTrue(retried.fp.closed)
            self.assertTrue(final.fp.closed)
    def test_invalid_webhook_and_verification_payload(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/"webhook"; path.write_text("https://example.test/private"); path.chmod(0o600)
            with self.assertRaises(DeliveryError): DiscordDelivery(DiscordConfig(path),Mock()).send(render(self.report(ReportItem(GROUP,REQUIRED))))
        with tempfile.TemporaryDirectory() as root:
            opener=Mock(); opener.open.return_value=Response(); DiscordDelivery(DiscordConfig(self.path(root)),opener).verify()
            self.assertEqual(json.loads(opener.open.call_args.args[0].data),{"content":"Soc Thief delivery verification: synthetic payload only.","allowed_mentions":{"parse":[]}})
    def test_every_request_names_a_fixed_user_agent(self):
        # Without one, urllib sends "Python-urllib/3.x", which Discord's Cloudflare front refuses
        # with 403 / error 1010 - measured on the first synthetic verification.
        with tempfile.TemporaryDirectory() as root:
            opener=Mock(); opener.open.return_value=Response(); delivery=DiscordDelivery(DiscordConfig(self.path(root)),opener)
            delivery.verify(); delivery.send(render(self.report(ReportItem(GROUP,REQUIRED))))
            for call in opener.open.call_args_list: self.assertEqual(call.args[0].get_header("User-agent"),f"SocThief/{__version__}")
    def test_file_path_environment_is_required(self):
        with self.assertRaises(DeliveryError): DiscordConfig.from_environment({})
    def test_unsafe_secret_file_is_sanitized(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/"webhook"; path.write_text("synthetic"); path.chmod(0o644)
            with self.assertRaisesRegex(DeliveryError,"configuration is invalid"):
                DiscordDelivery(DiscordConfig(path),Mock()).verify()


KNOWN_AGENT = {("baseline-only", "001"): (30, 30)}  # Agent 001 is known; its rules below are not.


class DigestTest(unittest.TestCase):
    """Compact message, recurring totals, and an exact attached group listing."""
    START, END = datetime(2026,1,1,tzinfo=timezone.utc), datetime(2026,1,2,tzinfo=timezone.utc)
    def group(self, rule, agent="001", level=3, count=4, description="Synthetic event"):
        return {**GROUP, "rule_id": rule, "agent_id": agent, "rule_level": level, "count": count, "rule_description": description}
    def digest(self, items, baseline, **counts):
        return render(Report(self.START, self.END, tuple(items), 0, counts.pop("health", 0), baseline=baseline, **counts))

    def test_breach_groups_lead_the_digest_one_line_each(self):
        # A breach line comes before failed and critical lines whatever its severity.
        items = [ReportItem(self.group("crit", level=15), Decision(True, False, "critical_severity")),
                 ReportItem(self.group("fail"), Decision(True, True, "invalid_model_result")),
                 *(ReportItem(self.group(f"crit-{index}", level=12), Decision(True, False, "critical_severity"))
                   for index in range(5)),
                 ReportItem(self.group("5902", level=8), Decision(True, False, "breach_account_created")),
                 ReportItem(self.group("60117", level=9), Decision(True, False, "breach_log_cleared"))]
        output = self.digest(items, KNOWN_AGENT)
        lines = [line for line in output.payloads[0]["content"].splitlines() if line.startswith("• ")]
        self.assertEqual([line.split("**")[1] for line in lines[:3]],
                         ["BREACH log cleared", "BREACH account created", "FAILED"])
        self.assertIn("BREACH account created | 8 | 5902", output.attachment)

    def test_paged_report_puts_breach_groups_on_page_one(self):
        items = [ReportItem(self.group(str(index), level=15, description="x" * 680), REQUIRED) for index in range(30)]
        items.append(ReportItem(self.group("5902", level=3), Decision(True, False, "breach_account_created")))
        content = render(Report(self.START, self.END, tuple(items), 0, 0)).payloads[0]["content"]
        self.assertIn("**BREACH account created** Rule `5902`", content)

    def test_large_critical_day_summarizes_message_but_keeps_exact_attachment(self):
        items = [ReportItem(self.group(f"synthetic-{index}", level=12, count=1,
                                       description=f"Synthetic critical variant {index}"),
                            Decision(True, False, "critical_severity")) for index in range(356)]
        output = self.digest(items, {})
        self.assertFalse(output.truncated)
        self.assertEqual(output.omitted_count, 0)
        self.assertEqual(len(output.payloads), 1)
        messages = "\n".join(payload["content"] for payload in output.payloads)
        self.assertIn("Critical: 356 groups, 356 events; 3 examples below", messages)
        self.assertEqual(messages.count("**CRITICAL**"), 3)
        self.assertNotIn("`synthetic-355`", messages)
        self.assertEqual(sum(line.startswith("CRITICAL | ") for line in output.attachment.splitlines()), 356)
        for index in range(356):
            self.assertIn(f" | synthetic-{index} | ", output.attachment)

    def test_critical_compaction_does_not_hide_failed_groups(self):
        critical = [ReportItem(self.group(f"critical-{index}", level=12),
                               Decision(True, False, "critical_severity")) for index in range(60)]
        failed = [ReportItem(self.group(f"failed-{index}"),
                             Decision(True, True, "invalid_model_result")) for index in range(4)]
        output = self.digest(critical + failed, {})
        messages = "\n".join(payload["content"] for payload in output.payloads)
        self.assertFalse(output.truncated)
        self.assertEqual(messages.count("**CRITICAL**"), 3)
        self.assertEqual(messages.count("**FAILED**"), 4)
        self.assertEqual(sum(line.startswith("CRITICAL | ") for line in output.attachment.splitlines()), 60)

    def test_failures_precede_high_severity_new_groups_and_agent_summaries(self):
        # A low-severity boundary failure used to be buried behind NEW groups, while
        # all NEW AGENT summaries were unconditionally prepended ahead of it.
        items = [ReportItem(self.group(f"new-{index}", level=10, description="x" * 300), REQUIRED)
                 for index in range(40)]
        items.append(ReportItem(self.group("new-agent", agent="009", level=10), REQUIRED))
        items.append(ReportItem(self.group("failed", level=3),
                                Decision(True, True, "invalid_model_result")))
        output = self.digest(items, KNOWN_AGENT, health=1)
        first = output.payloads[0]["content"]
        self.assertGreater(len(output.payloads), 1)
        self.assertIn("**FAILED** sev 3 `failed`", first)
        messages = "\n".join(page["content"] for page in output.payloads)
        self.assertLess(messages.index("**FAILED**"), messages.index("**NEW**"))
        self.assertLess(messages.index("**FAILED**"), messages.index("**NEW AGENT**"))
        rows = [line for line in output.attachment.splitlines() if " | " in line]
        self.assertTrue(rows[1].startswith("FAILED | "))
        self.assertEqual(sum(line.startswith("NEW | ") for line in rows), 40)

    def test_categories_itemise_what_changed_and_collapse_the_rest(self):
        items = [ReportItem(self.group("crit", level=13, count=1), Decision(True, False, "critical_severity")),
                 ReportItem(self.group("fail"), Decision(True, True, "invalid_model_result")),
                 ReportItem(self.group("new"), REQUIRED),
                 ReportItem(self.group("spike", count=50), REQUIRED),
                 ReportItem(self.group("steady", count=12), REQUIRED),
                 ReportItem(self.group("quiet", count=9), REQUIRED)]
        # "crit" is in the baseline at normal volume: it stays in the attachment and is
        # shown among the first three critical examples.
        baseline = {("crit", "001"): (30, 30), ("fail", "001"): (30, 30), ("spike", "001"): (30, 30),
                    ("steady", "001"): (300, 30), ("quiet", "001"): (1, 1)}
        output = self.digest(items, baseline)
        self.assertEqual(len(output.payloads), 1); self.assertFalse(output.truncated)
        message = output.payloads[0]["content"]
        for tag, rule in [("CRITICAL", "crit"), ("FAILED", "fail"), ("NEW", "new"), ("SPIKE", "spike")]:
            self.assertIn(f"**{tag}** sev", message); self.assertIn(f"`{rule}`", message)
        # 9 events against a 1-a-day history is under the spike minimum; 12 against 10/day is not 3x.
        self.assertIn("__Needs a look — 4 groups, 4 message lines__", message)
        self.assertIn("__Recurring — 2 groups across 2 rules, 21 events__", message)
        self.assertIn("6 groups, 80 events", message)
        lines = output.attachment.splitlines()
        for category, rule in [("CRITICAL", "crit"), ("FAILED", "fail"), ("NEW", "new"), ("SPIKE", "spike"),
                               ("recurring", "steady"), ("recurring", "quiet")]:
            self.assertEqual(sum(line.startswith(f"{category} | ") and f" | {rule} | " in line for line in lines), 1, rule)
        self.assertEqual(output.payloads[0]["allowed_mentions"], {"parse": []})

    def test_a_new_agent_is_one_flagged_line_but_every_group_is_attached(self):
        # Measured: both 50+ NEW bursts in 61 real days were one newly enrolled agent.
        items = [ReportItem(self.group(f"r{index}", agent="009", count=2), REQUIRED) for index in range(40)]
        items.append(ReportItem(self.group("crit", agent="009", level=13, count=1), Decision(True, False, "critical_severity")))
        items.append(ReportItem(self.group("known", agent="001"), REQUIRED))
        output = self.digest(items, {("other", "001"): (30, 30)})
        message = output.payloads[0]["content"]
        self.assertEqual(message.count("**NEW AGENT**"), 1)
        self.assertIn("**NEW AGENT** 009 — 40 groups, 80 events, highest sev 3", message)
        self.assertIn("**CRITICAL** sev 13 `crit`", message)  # Never folded into the agent line.
        self.assertIn("**NEW** sev 3 `known`", message)       # Known agent, new rule: still itemised.
        self.assertIn("__Needs a look — 42 groups, 3 message lines__", message)
        self.assertEqual(sum(line.startswith("NEW AGENT | ") for line in output.attachment.splitlines()), 40)
        self.assertEqual(len(output.payloads), 1)

    def test_attachment_is_redacted_plain_text(self):
        output = self.digest([ReportItem(GROUP, REQUIRED)], {})
        self.assertIn("[masked IP]", output.attachment); self.assertNotIn("192.0.2.1", output.attachment)
        self.assertNotIn("token=private", output.attachment)
        self.assertNotIn("\\", output.attachment)  # No markdown escaping in the file.
        self.assertNotIn("192.0.2.1", output.payloads[0]["content"])

    def test_nothing_new_still_renders_totals_and_the_attachment(self):
        output = self.digest([ReportItem(self.group("steady"), REQUIRED)], {("steady", "001"): (120, 30)},
                             muted_groups=3, muted_events=900)
        message = output.payloads[0]["content"]
        self.assertIn("nothing new, spiking or critical", message)
        self.assertIn("Muted: 900 events in 3 groups.", message)
        self.assertIn(" | steady | ", output.attachment)

    def test_jev_trial_orders_recurring_and_keeps_every_group_attached(self):
        items = [ReportItem(self.group("low", count=20), REQUIRED, 0.12),
                 ReportItem(self.group("high", count=2), REQUIRED, 0.88),
                 ReportItem(self.group("critical", level=13), Decision(True, False, "critical_severity"))]
        baseline = {("low", "001"): (600, 30), ("high", "001"): (60, 30),
                    ("critical", "001"): (120, 30)}
        output = self.digest(items, baseline)
        message = output.payloads[0]["content"]
        self.assertIn("**CRITICAL**", message)
        self.assertLess(message.index("Jev 0.88"), message.index("Jev 0.12"))
        self.assertIn("uncalibrated; threat tags are unvalidated advice; ordering only", message)
        self.assertEqual(sum(line.startswith("recurring | ") for line in output.attachment.splitlines()), 2)
        self.assertIn(" | 0.88", output.attachment)
        self.assertFalse(output.truncated)

    def test_recurring_rule_shows_description_from_its_highest_scored_variant(self):
        items = [ReportItem(self.group("same", description="quiet variant"), REQUIRED, 0.10),
                 ReportItem(self.group("same", description="review variant"), REQUIRED, 0.90)]
        message = self.digest(items, {("same", "001"): (120, 30)}).payloads[0]["content"]
        self.assertIn("Jev 0.90", message)
        self.assertIn("review variant", message)
        self.assertNotIn("quiet variant", message)

    def test_attachment_keeps_score_when_description_is_truncated(self):
        item = ReportItem(self.group("long", description="x" * 1000), REQUIRED, 0.91)
        output = self.digest([item], {("long", "001"): (120, 30)})
        row = next(line for line in output.attachment.splitlines() if line.startswith("recurring | "))
        self.assertTrue(row.endswith(" | 0.91 | "))

    def test_jev_threat_tag_is_advice_and_kept_in_attachment(self):
        item = ReportItem(self.group("advice"), REQUIRED, 0.91, "other_concern")
        output = self.digest([item], {("advice", "001"): (120, 30)})
        self.assertIn("Jev 0.91 [other concern]", output.payloads[0]["content"])
        self.assertIn(" | 0.91 | other_concern", output.attachment)
        self.assertFalse(output.truncated)
        for bad in ("siem", "other_concern\nalert", True):
            with self.subTest(bad=bad), self.assertRaises(RendererError):
                self.digest([ReportItem(self.group("advice"), REQUIRED, 0.91, bad)], {})

    def test_flagged_overflow_pages_then_counts_what_no_page_carries(self):
        items = [ReportItem(self.group(f"r{index}", description="x" * 400), REQUIRED) for index in range(300)]
        output = self.digest(items, KNOWN_AGENT)
        self.assertGreater(len(output.payloads), 1); self.assertLessEqual(len(output.payloads), MAX_PAGES)
        self.assertTrue(output.truncated); self.assertGreater(output.omitted_count, 0)
        self.assertIn(f"[health review] Groups omitted from the messages: {output.omitted_count}", output.payloads[0]["content"])
        self.assertEqual(sum(line.startswith("NEW | ") for line in output.attachment.splitlines()), 300)
        for payload in output.payloads: self.assertLessEqual(len(payload["content"]), 1900)

    def test_attachment_budget_is_counted_not_silently_cut(self):
        items = [ReportItem(self.group(f"r{index}", description="x" * 380), REQUIRED) for index in range(20)]
        with patch("soc_thief.delivery.ATTACHMENT_LIMIT", 1024 + 2000):
            output = self.digest(items, {(f"r{index}", "001"): (120, 30) for index in range(20)})
        self.assertTrue(output.truncated)
        self.assertIn("did not fit in the attachment", output.payloads[0]["content"])
        self.assertIn("groups did not fit in this file", output.attachment)

    def test_invalid_baseline_is_refused(self):
        for bad in ([("r", "a")], {("r",): (1, 1)}, {("r", "a"): (1,)}, {("r", "a"): (-1, 1)}, {("r", 1): (1, 1)}):
            with self.subTest(bad=bad), self.assertRaises(RendererError):
                self.digest([ReportItem(GROUP, REQUIRED)], bad)

    def test_attachment_is_uploaded_with_page_one_only(self):
        items = [ReportItem(self.group(f"r{index}", description="x" * 400), REQUIRED) for index in range(30)]
        output = self.digest(items, KNOWN_AGENT)
        self.assertGreater(len(output.payloads), 1)
        with tempfile.TemporaryDirectory() as root:
            opener = Mock(); opener.open.return_value = Response()
            DiscordDelivery(DiscordConfig(DeliveryTest.path(None, root)), opener).send(output)
        first, *rest = [call.args[0] for call in opener.open.call_args_list]
        kind = first.get_header("Content-type")
        self.assertTrue(kind.startswith("multipart/form-data; boundary=soc-thief-"))
        boundary = kind.split("boundary=")[1].encode()
        parts = first.data.split(b"--" + boundary)
        self.assertEqual(len(parts), 4); self.assertEqual(parts[-1], b"--\r\n")
        head, body = parts[1].split(b"\r\n\r\n", 1)
        self.assertIn(b'name="payload_json"', head)
        described = json.loads(body[:-2])
        self.assertEqual(described["allowed_mentions"], {"parse": []})
        self.assertEqual(described["attachments"], [{"id": 0, "filename": "soc-thief-report.txt"}])
        head, body = parts[2].split(b"\r\n\r\n", 1)
        self.assertIn(b'name="files[0]"; filename="soc-thief-report.txt"', head)
        self.assertEqual(body[:-2].decode(), output.attachment)
        self.assertEqual(first.get_header("User-agent"), f"SocThief/{__version__}")
        for request in rest:
            self.assertEqual(request.get_header("Content-type"), "application/json")
            self.assertNotIn(b"soc-thief-report", request.data)
