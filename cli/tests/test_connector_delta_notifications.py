# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""No-network tests for informative GitHub notices and privacy boundaries."""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cli.tests.test_connector_delta_inventory import fetcher, pr
from cli.tests.test_connector_delta_monitor import snapshot
from scripts.connector_delta import inventory, monitor
from scripts.connector_delta import notifications as n


class FakeGitHub:
    repository = "cisco-ai-defense/defenseclaw"
    author = "github-actions[bot]"

    def __init__(self):
        self.issues, self.comments, self.calls = [], [], []

    def pages(self, resource):
        return iter(self.comments if "/comments" in resource else self.issues)

    def request(self, method, resource, payload=None):
        self.calls.append((method, resource, payload))
        if method == "PATCH":
            self.issues[0].update(payload)
        elif resource.endswith("/comments"):
            self.comments.append({"body": payload["body"], "user": {"login": self.author}})
        else:
            self.issues.append({**payload, "number": 1, "state": "open", "user": {"login": self.author}})
        return {}


def informative_report():
    manifest = monitor.load_manifest()
    value = snapshot()
    _, state = monitor.run_monitor(value, manifest)
    value["pr_inventory"] = inventory.collect(manifest, fetcher([pr()], ["examples/settings/settings-hipaa.json"]))
    return monitor.run_monitor(value, manifest, state)


class NotificationTests(unittest.TestCase):
    def test_informative_review_is_sent_without_breaking_change(self):
        report, _ = informative_report()
        self.assertNotIn("breaking_change", report["summary"])
        api = FakeGitHub()
        result = n.notify(n.envelope(report), api)
        self.assertEqual(result["status"], "created")
        body = api.issues[0]["body"]
        for text in (
            "@ihabler",
            "@habler-code",
            "@vineethsai",
            "@vineethsai7",
            "@sanjayab23",
            "settings-hipaa.json",
            "What to inspect",
            "Zero watched changes",
        ):
            self.assertIn(text, body)
        self.assertIn("https://github.com/anthropics/claude-code/pull/100293", body)

    def test_repeated_findings_are_not_mailed_again(self):
        report, _ = informative_report()
        api = FakeGitHub()
        value = n.envelope(report)
        n.notify(value, api)
        self.assertEqual(n.notify(value, api)["status"], "deduplicated")
        self.assertEqual(len(api.calls), 1)

    def test_tracker_lookup_filters_bot_author_instead_of_all_repository_prs(self):
        report, _ = informative_report()
        api = FakeGitHub()
        with patch.object(api, "pages", wraps=api.pages) as pages:
            n.notify(n.envelope(report), api)
        self.assertIn("creator=github-actions%5Bbot%5D", pages.call_args_list[0].args[0])

    def test_new_review_comments_on_existing_tracker_and_mentions_owners(self):
        report, _ = informative_report()
        api = FakeGitHub()
        value = n.envelope(report)
        n.notify(value, api)
        newer = copy.deepcopy(value)
        newer["items"][0]["id"] = "d" * 64
        self.assertEqual(n.notify(newer, api)["status"], "commented")
        self.assertIn("@ihabler", api.comments[0]["body"])
        self.assertEqual(n.notify(newer, api)["status"], "deduplicated")

    def test_closed_tracker_only_reopens_for_a_new_signal(self):
        report, _ = informative_report()
        api = FakeGitHub()
        value = n.envelope(report)
        n.notify(value, api)
        api.issues[0]["state"] = "closed"
        n.notify(value, api)
        self.assertEqual(api.issues[0]["state"], "closed")
        value["items"][0]["id"] = "e" * 64
        n.notify(value, api)
        self.assertEqual(api.issues[0]["state"], "open")

    def test_no_new_changes_is_quiet_not_automatic_incident_resolution(self):
        api = FakeGitHub()
        self.assertEqual(n.notify({"schema_version": 1, "connector": "codex", "items": []}, api)["status"], "quiet")
        self.assertFalse(api.calls)

    def test_untrusted_user_cannot_forge_the_bot_dedup_marker(self):
        report, _ = informative_report()
        api = FakeGitHub()
        n.notify(n.envelope(report), api)
        api.issues[0]["user"]["login"] = "untrusted-user"
        n.notify(n.envelope(report), api)
        self.assertEqual(len(api.issues), 2)

    def test_sensitive_conflict_evidence_is_not_in_public_envelope_or_issue(self):
        report, _ = informative_report()
        finding = report["findings"][0]
        finding.update(decision="breaking_change", analysis={"summary": "PRIVATE-SECRET-SENTINEL"})
        finding["candidate"]["text"] = "PRIVATE-SECRET-SENTINEL"
        value = n.envelope(report)
        self.assertNotIn("PRIVATE-SECRET-SENTINEL", json.dumps(value))
        api = FakeGitHub()
        n.notify(value, api)
        self.assertNotIn("PRIVATE-SECRET-SENTINEL", api.issues[0]["body"])
        self.assertNotIn("hook.decision", api.issues[0]["body"])

    def test_public_projection_strips_model_cache_and_full_report(self):
        report, state = informative_report()
        report["private_analysis"] = "PRIVATE-SECRET-SENTINEL"
        state["cache"] = {"cached": {"summary": "PRIVATE-SECRET-SENTINEL"}}
        with tempfile.TemporaryDirectory() as directory:
            n.publish(report, state, directory)
            for path in Path(directory).iterdir():
                self.assertNotIn("PRIVATE-SECRET-SENTINEL", path.read_text())
            self.assertEqual(monitor.load_json(Path(directory) / "state.json")["cache"], {})

    def test_off_switch_does_not_read_envelope_or_touch_network(self):
        with (
            patch.dict(os.environ, {"CONNECTOR_DELTA_NOTIFICATIONS_ENABLED": "false"}),
            patch.object(n.GitHub, "request", side_effect=AssertionError("network")),
        ):
            self.assertEqual(n.main(["notify", "--envelope", "/missing.json"]), 0)

    def test_pending_notice_survives_source_progress_until_receipt(self):
        report, state = informative_report()
        with tempfile.TemporaryDirectory() as directory:
            n.publish(report, state, directory)
            checkpoint = monitor.load_json(Path(directory) / "state.json")
            self.assertTrue(checkpoint["notification_outbox"])
            empty = {**report, "findings": [], "gaps": []}
            n.publish(empty, checkpoint, directory)
            pending = monitor.load_json(Path(directory) / "notification.json")
            self.assertTrue(pending["items"])
            receipt = {
                "schema_version": 1,
                "connector": report["connector"],
                "sent": [item["id"] for item in pending["items"]],
            }
            n.publish(empty, checkpoint, directory, receipt)
            self.assertFalse(monitor.load_json(Path(directory) / "notification.json")["items"])
            self.assertFalse(monitor.load_json(Path(directory) / "state.json")["notification_outbox"])

    def test_failed_publisher_does_not_acknowledge_or_remove_pending_notice(self):
        report, state = informative_report()
        api = FakeGitHub()
        with tempfile.TemporaryDirectory() as directory:
            n.publish(report, state, directory)
            checkpoint = monitor.load_json(Path(directory) / "state.json")
            value = monitor.load_json(Path(directory) / "notification.json")
            with patch.object(api, "request", side_effect=ValueError("offline")), self.assertRaises(ValueError):
                n.notify(value, api)
            n.publish({**report, "findings": [], "gaps": []}, checkpoint, directory)
            self.assertEqual(monitor.load_json(Path(directory) / "notification.json"), value)

    def test_analyzer_signature_reset_preserves_notification_outbox(self):
        report, state = informative_report()
        state["signature"] = "old-implementation"
        state["notification_outbox"] = n.envelope(report)["items"]
        _, updated = monitor.run_monitor(snapshot(), monitor.load_manifest(), state)
        self.assertEqual(updated["notification_outbox"], state["notification_outbox"])

    def test_receipt_for_another_connector_is_refused(self):
        report, state = informative_report()
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            n.publish(report, state, directory, {"schema_version": 1, "connector": "codex", "sent": []})

    def test_private_fields_cannot_enter_notification_outbox(self):
        report, state = informative_report()
        item = n.envelope(report)["items"][0]
        state["notification_outbox"] = [{**item, "private_analysis": "PRIVATE-SECRET-SENTINEL"}]
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            n.publish(report, state, directory)

    def test_large_notice_batch_acknowledges_only_the_published_chunk(self):
        item = {"kind": "review", "title": "Public upstream review", "url": "", "files": [], "focus": ["x" * 1000] * 10}
        value = {
            "schema_version": 1,
            "connector": "codex",
            "items": [{**item, "id": n.fingerprint(index)} for index in range(100)],
        }
        api = FakeGitHub()
        first = n.notify(value, api)
        self.assertGreater(first["new_items"], 0)
        self.assertLess(first["new_items"], 100)
        self.assertEqual(len(first["acknowledged_ids"]), first["new_items"])
        second = n.notify(value, api)
        self.assertEqual(second["status"], "commented")
        self.assertGreater(len(second["acknowledged_ids"]), len(first["acknowledged_ids"]))
        self.assertLess(len(api.issues[0]["body"]), 60000)

    def test_malformed_notice_and_wrong_upstream_link_are_refused(self):
        report, _ = informative_report()
        for key, bad in (("id", "not-a-hash"), ("url", "https://attacker.example/pull/1")):
            value = n.envelope(report)
            value["items"][0][key] = bad
            api = FakeGitHub()
            with self.subTest(key=key), self.assertRaises(ValueError):
                n.notify(value, api)
            self.assertFalse(api.calls)

    def test_upstream_title_cannot_mention_arbitrary_users(self):
        report, _ = informative_report()
        report["findings"][0]["candidate"]["pr"]["title"] = "@unexpected-user <script> bad\ntext"
        api = FakeGitHub()
        n.notify(n.envelope(report), api)
        body = api.issues[0]["body"]
        self.assertNotIn("@unexpected-user", body)
        self.assertNotIn("<script>", body)

    def test_github_destination_and_missing_credentials_are_refused(self):
        for repo, token in (
            ("https://attacker.example/repo", "placeholder"),
            ("owner/../repo", "placeholder"),
            ("owner/repo", ""),
        ):
            with self.subTest(repo=repo), self.assertRaises(ValueError):
                n.GitHub(repo, token)

    def test_api_failure_never_logs_credential_or_response(self):
        api = n.GitHub("owner/repo", "PRIVATE-SECRET-SENTINEL")
        with patch("urllib.request.OpenerDirector.open", side_effect=OSError("PRIVATE-SECRET-SENTINEL")):
            with self.assertRaisesRegex(ValueError, "withheld") as caught:
                api.request("GET", "/repos/owner/repo/issues")
        self.assertNotIn("PRIVATE-SECRET-SENTINEL", str(caught.exception))

    def test_workflow_keeps_raw_evidence_out_of_public_artifacts(self):
        text = (monitor.ROOT / ".github/workflows/connector-delta-monitor.yml").read_text()
        self.assertIn("--include-pr-inventory", text)
        self.assertIn("path: monitor-public/state.json", text)
        self.assertNotIn("path: monitor-output/", text)
        self.assertIn("issues: write", text.split("  notify:", 1)[1])
        self.assertNotIn("issues: write", text.split("  notify:", 1)[0])
        self.assertNotIn("head -c 900000 monitor-output/report.md", text)


if __name__ == "__main__":
    unittest.main()
