# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Bounded merged-PR file inventory; unwatched changes are review, never safe."""

from __future__ import annotations

import hashlib
import json
import os
import re

from . import invariants

REPOSITORIES = {"codex": "openai/codex", "claudecode": "anthropics/claude-code"}
SHA = re.compile(r"[a-f0-9]{40}")


def collect(manifest, fetch, state=None):
    repo = REPOSITORIES[manifest["connector"]]
    prior = (state or {}).get("pr_inventory", {})
    watermark = prior.get("watermark", "")
    seen = set(prior.get("seen", []))
    result = {"repository": repo, "prs": [], "errors": [], "watermark": watermark, "deferred": 0}
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    rows = []
    for page in range(1, 4):
        batch = json.loads(
            fetch(
                f"https://api.github.com/repos/{repo}/pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page={page}",
                headers=headers,
            )
        )
        if not isinstance(batch, list) or len(batch) > 100:
            raise ValueError("invalid upstream PR list")
        rows.extend(batch)
        if len(batch) < 100 or (watermark and batch[-1].get("updated_at", "") <= watermark):
            break
    else:
        if watermark and rows[-1].get("updated_at", "") > watermark:
            result["errors"].append("PR inventory window does not reach the previous checkpoint")
    merged = []
    for row in rows:
        if not row.get("merged_at") or row.get("base", {}).get("ref") != "main":
            continue
        number, revision, date = row.get("number"), row.get("merge_commit_sha"), row.get("merged_at")
        if type(number) is not int or number <= 0 or not isinstance(revision, str) or not SHA.fullmatch(revision):
            raise ValueError("invalid merged PR identity")
        if not isinstance(date, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", date):
            raise ValueError("invalid PR merge timestamp")
        if str(number) not in seen and (not watermark or date >= watermark):
            merged.append(row)
    merged.sort(key=lambda row: (row["merged_at"], row["number"]))
    # First run intentionally looks at the latest ten, not all historical PRs.
    selected = merged[-10:] if not watermark else merged[:10]
    result["deferred"] = max(0, len(merged) - 10) if watermark else 0
    watched = {source.get("path", source["url"].rsplit("/", 1)[-1]) for source in manifest["sources"]}
    for row in selected:
        number, files, complete = row["number"], [], False
        for page in range(1, 11):
            batch = json.loads(
                fetch(
                    f"https://api.github.com/repos/{repo}/pulls/{number}/files?per_page=100&page={page}",
                    headers=headers,
                )
            )
            if not isinstance(batch, list) or len(batch) > 100:
                raise ValueError("invalid PR file inventory")
            for item in batch:
                path = item.get("filename")
                if not isinstance(path, str) or not path or len(path) > 1000:
                    raise ValueError("invalid changed-file path")
                old_path = item.get("previous_filename", path)
                if not isinstance(old_path, str) or len(old_path) > 1000:
                    raise ValueError("invalid previous changed-file path")
                matches = [
                    rule
                    for rule in manifest["pr_inventory"]["paths"]
                    if re.search(rule["pattern"], path) or re.search(rule["pattern"], old_path)
                ]
                if matches and (path not in watched or old_path != path):
                    files.append(
                        {
                            "path": path,
                            "invariants": sorted({key for match in matches for key in match["invariants"]}),
                            "review_focus": sorted({match["review_focus"] for match in matches}),
                        }
                    )
            if len(batch) < 100:
                complete = True
                break
        if not complete:
            result["errors"].append(f"PR {number} exceeds the 1000-file inventory bound")
        result["prs"].append(
            {
                "number": number,
                "revision": row["merge_commit_sha"],
                "merged_at": row["merged_at"],
                "title": str(row.get("title", ""))[:300],
                "url": f"https://github.com/{repo}/pull/{number}",
                "changed_files": files,
                "complete": complete,
            }
        )
    return result


def apply(snapshot, manifest, provider, report, state):
    inventory = snapshot.get("pr_inventory")
    if inventory is None:
        report["pr_inventory"] = {"status": "not_collected", "reason": "PR inventory was not requested for this replay"}
        return
    if not isinstance(inventory, dict) or inventory.get("repository") != REPOSITORIES[manifest["connector"]]:
        raise ValueError("invalid inventory repository")
    prior = state.setdefault("pr_inventory", {"watermark": "", "seen": []})
    seen = set(prior["seen"])
    prs = inventory.get("prs", [])
    if not isinstance(prs, list) or len(prs) > 10:
        raise ValueError("invalid inventory batch")
    for pr in prs:
        number = pr.get("number")
        if (
            type(number) is not int
            or number <= 0
            or pr.get("url") != f"https://github.com/{inventory['repository']}/pull/{number}"
        ):
            raise ValueError("invalid inventory PR URL")
        if str(number) in seen or not pr.get("complete"):
            continue
        files = pr.get("changed_files", [])
        if files:
            selected = sorted({key for item in files for key in item["invariants"]})
            checks = invariants.evaluate(
                provider.catalog,
                provider.local(),
                [],
                selected=selected,
                transport=provider.transport,
                texts=provider.texts,
            )
            text = pr["title"] + "\n" + "\n".join(item["path"] for item in files)
            candidate = {
                "id": hashlib.sha256((pr["url"] + pr["revision"] + text).encode()).hexdigest(),
                "source": "upstream-pr-inventory",
                "source_revision": pr["revision"],
                "url": pr["url"],
                "kind": "pr_inventory",
                "text": text,
                "pr": pr,
            }
            report["findings"].append(
                {
                    "candidate": candidate,
                    "decision": "review_required",
                    "impact": "unknown",
                    "analysis_status": "unwatched_pr_artifact",
                    "artifact_classes": ["pr_inventory_gap"],
                    "risk_hints": ["coverage"],
                    "invariants": checks,
                    "local_artifacts": sorted({ref["artifact"] for check in checks for ref in check["local_evidence"]}),
                    "recommended_tests": [],
                    "unknowns": [
                        "Hook-related files changed outside the deterministic watchlist; "
                        "review is needed, not a proven regression."
                    ],
                }
            )
        seen.add(str(number))
    if not inventory.get("errors"):
        dates = [pr["merged_at"] for pr in prs if pr.get("complete")]
        if dates:
            prior["watermark"] = max(prior["watermark"], max(dates))
    prior["seen"] = sorted(seen, key=int)[-2000:]
    for reason in inventory.get("errors", []):
        report["gaps"].append({"source": "upstream-pr-inventory", "decision": "collection_gap", "reason": reason})
    if inventory.get("deferred"):
        report["gaps"].append(
            {
                "source": "upstream-pr-inventory",
                "decision": "collection_gap",
                "reason": "Additional merged PRs remain queued for the next bounded run",
            }
        )
    report["pr_inventory"] = {
        "status": "compared",
        "prs": len(prs),
        "scope": "Up to 300 updated closed PRs; ten merged PRs per batch; initial latest ten only.",
    }
