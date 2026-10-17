# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Sanitized GitHub notices; GitHub email delivery follows recipient settings.

Full reports and AI caches never cross into the write-permission publisher job.
Only public upstream metadata and code-owned review instructions are published.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import monitor

LIMIT = 200
OUTBOX_LIMIT = 1000
KINDS = {"review", "contract_conflict", "health"}
NOTICE = (
    "Zero watched changes is not proof that the connector is safe. Static analysis is not live-client verification."
)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def safe_text(value, limit=300):
    value = "".join(char for char in str(value) if char.isprintable())[:limit]
    return html.escape(value).replace("@", "&#64;").replace("[", "&#91;").replace("]", "&#93;").replace("`", "&#96;")


def envelope(report):
    connector = report["connector"]
    if connector not in monitor.PROVIDERS:
        raise ValueError("unsupported notification connector")
    manifest = monitor.load_manifest(monitor.CONFIG / "connectors" / connector / "manifest.json")
    items = []
    for finding in report["findings"]:
        if finding["decision"] == "filtered":
            continue
        candidate = finding["candidate"]
        key = fingerprint([connector, candidate["id"], finding["decision"]])
        if finding["decision"] == "breaking_change":
            # Do not publish a bypass recipe, invariant name, value or evidence.
            items.append(
                {
                    "id": key,
                    "kind": "contract_conflict",
                    "title": "A concrete contract conflict requires private maintainer review",
                    "url": "",
                    "files": [],
                    "focus": [],
                }
            )
            continue
        pr = candidate.get("pr")
        files, focus, url = [], [], ""
        title = "Upstream hook-related change needs review"
        if pr:
            repo = {"codex": "openai/codex", "claudecode": "anthropics/claude-code"}[connector]
            number = pr["number"]
            if type(number) is not int or number <= 0:
                raise ValueError("invalid PR number")
            url = f"https://github.com/{repo}/pull/{number}"
            title = safe_text(pr["title"])
            for changed in pr["changed_files"][:30]:
                path = changed["path"]
                if not re.fullmatch(r"[A-Za-z0-9_./-]{1,300}", path):
                    continue
                files.append(path)
                for rule in manifest["pr_inventory"]["paths"]:
                    if re.search(rule["pattern"], path):
                        focus.append(rule["review_focus"])
        else:
            title += " (" + safe_text(candidate.get("version", candidate["source"])) + ")"
            focus.append(
                "Inspect registered events, payloads, deny responses and execution assumptions. "
                "No runtime break has been established."
            )
        items.append(
            {"id": key, "kind": "review", "title": title, "url": url, "files": files, "focus": sorted(set(focus))}
        )
    if report["gaps"]:
        items.append(
            {
                "id": fingerprint([connector, report["gaps"]]),
                "kind": "health",
                "title": "Collection or analysis coverage is incomplete",
                "url": "",
                "files": [],
                "focus": [
                    "Inspect the collector and checkpoint locally; an incomplete run must not be read as compatibility."
                ],
            }
        )
    if len(items) > OUTBOX_LIMIT:
        raise ValueError("notification backlog exceeds 1000 items; review locally before publishing")
    return {"schema_version": 1, "connector": connector, "items": items}


def public_checkpoint(state, manifest):
    # Source snapshots contain only the collector's allowlisted public data.
    # Successful model output is intentionally not persisted as a public cache.
    allowed = {"id", "kind", "url", "revision", "collected_revision", "content_sha256", "text"}
    result = {"schema_version": 1, "cache": {}, "signature": state.get("signature")}
    for key in ("sources", "pending_sources"):
        sources = state.get(key, {})
        monitor.check_snapshot({"schema_version": 1, "sources": list(sources.values())}, manifest)
        result[key] = {
            name: {key: value for key, value in row.items() if key in allowed} for name, row in sources.items()
        }
    if "pr_inventory" in state:
        prior = state["pr_inventory"]
        seen, watermark = prior.get("seen", []), prior.get("watermark", "")
        if (
            not isinstance(seen, list)
            or len(seen) > 2000
            or any(not re.fullmatch(r"[1-9]\d*", value) for value in seen)
        ):
            raise ValueError("invalid inventory checkpoint")
        if watermark and not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", watermark):
            raise ValueError("invalid inventory watermark")
        result["pr_inventory"] = {"seen": seen, "watermark": watermark}
    return result


def validate_envelope(value, limit=LIMIT):
    if value.get("schema_version") != 1 or value.get("connector") not in monitor.PROVIDERS:
        raise ValueError("invalid notification envelope")
    items = value.get("items")
    if not isinstance(items, list) or len(items) > limit:
        raise ValueError("invalid notification batch")
    for item in items:
        if not isinstance(item, dict) or set(item) != {"id", "kind", "title", "url", "files", "focus"}:
            raise ValueError("invalid notification item")
        if (
            item["kind"] not in KINDS
            or not isinstance(item["id"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", item["id"])
        ):
            raise ValueError("invalid notification identity")
        if not isinstance(item["title"], str) or len(item["title"]) > 2000 or not isinstance(item["url"], str):
            raise ValueError("invalid notification text")
        if item["url"]:
            repo = {"codex": "openai/codex", "claudecode": "anthropics/claude-code"}[value["connector"]]
            if not re.fullmatch(r"https://github\.com/" + re.escape(repo) + r"/pull/[1-9]\d*", item["url"]):
                raise ValueError("invalid upstream notification link")
        if (
            not isinstance(item["files"], list)
            or len(item["files"]) > 30
            or any(
                not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,300}", path) for path in item["files"]
            )
        ):
            raise ValueError("invalid notification paths")
        if (
            not isinstance(item["focus"], list)
            or len(item["focus"]) > 10
            or any(not isinstance(text, str) or len(text) > 1000 for text in item["focus"])
        ):
            raise ValueError("invalid review instructions")
        if item["kind"] == "contract_conflict" and (item["url"] or item["files"] or item["focus"]):
            raise ValueError("private conflict evidence must not cross the public boundary")
    return items


def publish(report, state, directory, receipt=None):
    directory = Path(directory)
    notices = envelope(report)
    prior = {**notices, "items": state.get("notification_outbox", [])}
    validate_envelope(prior, OUTBOX_LIMIT)
    acknowledged = set()
    if receipt:
        acknowledged = set(receipt.get("sent", []))
        if (
            receipt.get("schema_version") != 1
            or receipt.get("connector") != report["connector"]
            or len(acknowledged) > LIMIT
            or any(not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{64}", key) for key in acknowledged)
        ):
            raise ValueError("invalid notification receipt")
    pending = {item["id"]: item for item in prior["items"] if item["id"] not in acknowledged}
    pending.update({item["id"]: item for item in notices["items"] if item["id"] not in acknowledged})
    if len(pending) > OUTBOX_LIMIT:
        raise ValueError("notification backlog exceeds bound; checkpoint retained for operator recovery")
    notices["items"] = list(pending.values())[:LIMIT]
    checkpoint = public_checkpoint(
        state, monitor.load_manifest(monitor.CONFIG / "connectors" / report["connector"] / "manifest.json")
    )
    checkpoint["notification_outbox"] = list(pending.values())
    public = {
        "schema_version": 1,
        "connector": report["connector"],
        "outcome": report["outcome"],
        "attention_required": bool(notices["items"]),
        "notice": NOTICE,
        "details": "Full evidence stays local to the analysis runner; reproduce locally for private investigation.",
    }
    monitor.write_json(directory / "report.json", public)
    monitor.write_json(directory / "notification.json", notices)
    monitor.write_json(directory / "state.json", checkpoint)
    review = "needed" if notices["items"] else "no new signal"
    monitor.write_text(
        directory / "report.md",
        f"# {report['connector']} upstream monitor\n\n{NOTICE}\n\n"
        f"Analysis: {report['outcome']}. Maintainer review: {review}.\n\n"
        "Full evidence and model output are deliberately not published in Actions artifacts.\n",
    )
    return public


class GitHub:
    def __init__(self, repository, token, author="github-actions[bot]"):
        if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", repository) or repository.endswith(("/.", "/..")):
            raise ValueError("invalid notification repository")
        if not token or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\[bot\])?", author):
            raise ValueError("notification token or expected author is missing")
        self.repository, self.token, self.author = repository, token, author

    def request(self, method, resource, payload=None):
        if not resource.startswith("/") or resource.startswith("//"):
            raise ValueError("invalid GitHub API resource")
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        opener = urllib.request.build_opener(monitor.NoRedirect(), urllib.request.HTTPSHandler(context=context))
        req = urllib.request.Request(
            "https://api.github.com" + resource,
            method=method,
            data=None if payload is None else json.dumps(payload).encode(),
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "DefenseClaw-Connector-Delta-Monitor/1",
            },
        )
        try:
            with opener.open(req, timeout=25) as response:
                content = response.read(monitor.MAX_BYTES + 1)
            if len(content) > monitor.MAX_BYTES:
                raise ValueError("notification response exceeds limit")
            return json.loads(content)
        except (urllib.error.URLError, OSError, ValueError):
            raise ValueError("GitHub notification request failed; credentials and response bodies withheld") from None

    def pages(self, resource):
        for page in range(1, 11):
            rows = self.request("GET", resource + ("&" if "?" in resource else "?") + f"per_page=100&page={page}")
            if not isinstance(rows, list) or len(rows) > 100:
                raise ValueError("invalid notification listing")
            yield from rows
            if len(rows) < 100:
                return
        raise ValueError("notification history exceeds bounds; refusing to silently duplicate alerts")


def notify(value, api, *, run_url=""):
    items = validate_envelope(value)
    if not items:
        return {"status": "quiet", "new_items": 0}
    connector = value["connector"]
    marker = f"<!-- defenseclaw-connector-monitor:{connector} -->"
    prefix = f"/repos/{api.repository}"
    issue = next(
        (
            row
            for row in api.pages(prefix + "/issues?state=all&creator=" + urllib.parse.quote(api.author, safe=""))
            if not row.get("pull_request")
            and marker in (row.get("body") or "")
            and row.get("user", {}).get("login") == api.author
        ),
        None,
    )
    previous = []
    if issue:
        previous.append(issue.get("body") or "")
        previous.extend(
            row.get("body") or ""
            for row in api.pages(prefix + f"/issues/{issue['number']}/comments")
            if row.get("user", {}).get("login") == api.author
        )
    seen = set(re.findall(r"<!-- signal:([a-f0-9]{64}) -->", "\n".join(previous)))
    new = [item for item in items if item["id"] not in seen]
    if not new:
        return {"status": "deduplicated", "new_items": 0, "acknowledged_ids": [item["id"] for item in items]}
    config = monitor.load_json(monitor.CONFIG / "shared/notifications.json")
    mentions = config["mentions"]
    if any(not re.fullmatch(r"[A-Za-z0-9_-]{1,39}", name) for name in mentions):
        raise ValueError("invalid configured maintainer handle")
    lines = [
        marker,
        " ".join("@" + name for name in mentions),
        "",
        NOTICE,
        "",
        "This is an informative upstream review notice, not a claim that a released client broke DefenseClaw.",
        "",
    ]
    published = []
    for item in new:
        previous_length = len(lines)
        title = (
            "A concrete incompatibility needs private review"
            if item["kind"] == "contract_conflict"
            else safe_text(item["title"])
        )
        lines += [f"### {title}", f"<!-- signal:{item['id']} -->"]
        # URL and names are public upstream metadata, never model output.
        if item["url"]:
            repo = {"codex": "openai/codex", "claudecode": "anthropics/claude-code"}[connector]
            if not re.fullmatch(r"https://github\.com/" + re.escape(repo) + r"/pull/[1-9]\d*", item["url"]):
                raise ValueError("invalid upstream notification link")
            lines += ["Upstream: " + item["url"]]
        if item["files"]:
            lines += [
                "Changed outside the configured watchlist: "
                + ", ".join("`" + safe_text(path) + "`" for path in item["files"])
            ]
        lines += ["What to inspect: " + safe_text(focus, 1000) for focus in item["focus"]]
        if item["kind"] == "contract_conflict":
            lines += [
                "Full invariant evidence is withheld. "
                "Reproduce locally and follow SECURITY.md for private investigation."
            ]
        lines += [""]
        if len("\n".join(lines)) > 50000:
            del lines[previous_length:]
            break
        published.append(item)
    if not published:
        raise ValueError("one notification exceeds the message bound")
    if run_url:
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/actions/runs/[1-9]\d*", run_url):
            raise ValueError("invalid workflow link")
        lines += ["Sanitized run summary: " + run_url]
    body = "\n".join(lines)
    if len(body) > 60000:
        raise ValueError("notification body exceeds bound; no alert sent")
    if issue:
        if issue.get("state") == "closed":
            api.request("PATCH", prefix + f"/issues/{issue['number']}", {"state": "open"})
        api.request("POST", prefix + f"/issues/{issue['number']}/comments", {"body": body})
        status = "commented"
    else:
        api.request(
            "POST",
            prefix + "/issues",
            {"title": f"[Connector monitor] {connector}: upstream changes to review", "body": body},
        )
        status = "created"
    acknowledged = [item["id"] for item in items if item["id"] in seen] + [item["id"] for item in published]
    return {"status": status, "new_items": len(published), "acknowledged_ids": acknowledged}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("publish", "notify"))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--envelope", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "publish":
            if not all((args.report, args.state, args.directory)):
                raise ValueError("publish requires report, state and directory")
            report = json.loads(monitor.read_text(args.report, 64 * 1024 * 1024))
            receipt = monitor.load_json(args.receipt) if args.receipt and args.receipt.exists() else None
            result = publish(report, monitor.load_json(args.state), args.directory, receipt)
        elif os.environ.get("CONNECTOR_DELTA_NOTIFICATIONS_ENABLED") != "true":
            result = {"status": "disabled", "new_items": 0}
        else:
            if not args.envelope:
                raise ValueError("notify requires an envelope")
            api = GitHub(
                os.environ.get("CONNECTOR_DELTA_ALERT_REPOSITORY") or os.environ.get("GITHUB_REPOSITORY", ""),
                os.environ.get("GH_TOKEN", ""),
                os.environ.get("CONNECTOR_DELTA_ALERT_AUTHOR") or "github-actions[bot]",
            )
            value = monitor.load_json(args.envelope)
            result = notify(value, api, run_url=os.environ.get("CONNECTOR_DELTA_RUN_URL", ""))
            if args.receipt:
                monitor.write_json(
                    args.receipt,
                    {
                        "schema_version": 1,
                        "connector": value["connector"],
                        "sent": result.get("acknowledged_ids", []),
                    },
                )
        print(json.dumps({key: value for key, value in result.items() if key != "acknowledged_ids"}))
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print("Connector notification failed; inspect configuration privately. No sensitive details were logged.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
