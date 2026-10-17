# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Bounded, pinned Codex history collection and offline parent-to-commit replay."""

from __future__ import annotations

import collections
import concurrent.futures
import json
import os
import re
import urllib.parse

from scripts.connector_delta.invariants import InvariantError


def collect_history(manifest, fetch, collector, *, count=15):
    if manifest["connector"] != "codex" or not 1 <= count <= 30:
        raise InvariantError("source history collection supports Codex only, with 1..30 commits")
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    commits = {}
    for path in ("codex-rs/hooks", "codex-rs/config/src/hook_config.rs"):
        query = urllib.parse.urlencode({"sha": "main", "path": path, "per_page": count})
        rows = json.loads(fetch("https://api.github.com/repos/openai/codex/commits?" + query, headers=headers))
        if not isinstance(rows, list) or len(rows) > count:
            raise InvariantError("invalid GitHub path history response")
        for row in rows:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("parents"), list)
                or not row["parents"]
                or not isinstance(row["parents"][0], dict)
                or not isinstance(row.get("commit"), dict)
                or not isinstance(row["commit"].get("committer"), dict)
                or not isinstance(row["commit"]["committer"].get("date"), str)
                or not isinstance(row["commit"].get("message"), str)
                or not row["commit"]["message"].strip()
            ):
                raise InvariantError("malformed GitHub history metadata")
            commit, parent = row.get("sha"), (row.get("parents") or [{}])[0].get("sha")
            if not all(isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{40}", sha) for sha in (commit, parent)):
                raise InvariantError("invalid history commit/parent SHA")
            commits[commit] = {
                "commit": commit,
                "parent": parent,
                "date": row["commit"]["committer"]["date"],
                "subject": row["commit"]["message"].splitlines()[0][:300],
            }
    cases = sorted(commits.values(), key=lambda row: row["date"], reverse=True)[:count]
    if not cases:
        raise InvariantError("upstream history was empty")
    revisions = sorted({sha for row in cases for sha in (row["commit"], row["parent"])})
    snapshots = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(collector, manifest, fetch, sha): sha for sha in revisions}
        for future in concurrent.futures.as_completed(futures):
            sha = futures[future]
            snapshots[sha] = future.result()
            print(f"Collected {len(snapshots)}/{len(revisions)} pinned source bundles", flush=True)
    return {
        "schema_version": 1,
        "connector": "codex",
        "scope": "Sampled commits reachable from main path history, each compared to its first parent. "
        "Not an exhaustive merged-PR feed or an as-of-time local-code experiment.",
        "cases": list(reversed(cases)),
        "snapshots": snapshots,
    }


def replay_history(history, manifest, runner, *, root, ai="off", model="", max_ai=10):
    if (
        not isinstance(history, dict)
        or history.get("schema_version") != 1
        or history.get("connector") != manifest["connector"]
        or not isinstance(history.get("cases"), list)
        or not 1 <= len(history["cases"]) <= 30
        or not isinstance(history.get("snapshots"), dict)
        or len(history["snapshots"]) > 60
    ):
        raise InvariantError("invalid history bundle")
    reports, remaining = [], max_ai
    for case in history["cases"]:
        if not isinstance(case, dict) or any(
            not isinstance(case.get(key), str) or not re.fullmatch(r"[a-f0-9]{40}", case[key])
            for key in ("parent", "commit")
        ):
            raise InvariantError("invalid history transition identity")
        before = history["snapshots"].get(case["parent"])
        after = history["snapshots"].get(case["commit"])
        if before is None or after is None:
            raise InvariantError("history snapshot missing; refusing to skip a transition")
        for sha, snapshot in ((case["parent"], before), (case["commit"], after)):
            if (
                not isinstance(snapshot, dict)
                or not isinstance(snapshot.get("sources"), list)
                or any(not isinstance(source, dict) or source.get("revision") != sha for source in snapshot["sources"])
            ):
                raise InvariantError("history snapshot does not match its transition revision")
        # Each delta is independent, not an invented chronological chain across
        # merged branches. The normal runner validates both pinned snapshots.
        _, state = runner(before, manifest, root=root, ai="off")
        if ai != "off":
            raise InvariantError(
                "historical source replay is deterministic; inspect emitted invariants before a separate AI run"
            )
        report, _ = runner(after, manifest, state, root=root, ai=ai, model=model, max_ai=remaining)
        # Missing baseline files are coverage gaps too; otherwise additions of
        # unavailable/renamed artifacts could look like benign first baselines.
        old_ids = {source["id"] for source in before["sources"]}
        for spec in manifest["sources"]:
            if spec["id"] not in old_ids:
                report["gaps"].append(
                    {
                        "source": spec["id"],
                        "decision": "collection_gap",
                        "reason": "parent snapshot source unavailable; transition not comparable",
                    }
                )
        report["outcome"] = "incomplete" if report["gaps"] else "complete"
        remaining -= report["ai_calls"]
        report["transition"] = case
        reports.append(report)
    result = dict(reports[-1])
    result.update(
        findings=[finding for report in reports for finding in report["findings"]],
        gaps=[{**gap, "commit": report["transition"]["commit"]} for report in reports for gap in report["gaps"]],
        replay_scope=str(history.get("scope", "Unspecified history scope"))[:1000],
        transitions=[
            {**report["transition"], "summary": report["summary"], "gaps": len(report["gaps"])} for report in reports
        ],
    )
    result["summary"] = dict(collections.Counter(row["decision"] for row in result["findings"]))
    result["invariant_summary"] = dict(
        collections.Counter(check["verdict"] for row in result["findings"] for check in row["invariants"])
    )
    result["ai_calls"] = max_ai - remaining
    result["outcome"] = "incomplete" if result["gaps"] else "complete"
    return result
