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
PATCH_REFERENCES = {
    "codex": r"\b(?:SessionStart(?:Source)?|PreToolUse|PostToolUse|PermissionRequest|HookStateToml|"
    r"HookTrustStatus|bypass_hook_trust|allow_managed_hooks_only|trusted_(?:content_)?hash)\b|hooks/(?:list|update)",
    "claudecode": r"\b(?:SessionStart|PreToolUse|PostToolUse|PermissionRequest|hookSpecificOutput|"
    r"permissionDecision|allowManagedHooksOnly|disableAllHooks)\b",
}


def file_scope(manifest, path, patch=None):
    """Routing hints, never compatibility proof; unknown code remains review."""
    if re.search(r"(?:^|/)(?:tests|testdata|snapshots|fixtures)/|(?:_tests|\.test)\.", path):
        return "informational", "Test/snapshot artifact; inspect it as evidence, not a new runtime regression."
    for rule in manifest.get("pr_inventory", {}).get("informational_paths", []):
        if not re.search(rule["pattern"], path):
            continue
        if rule.get("requires_patch"):
            if not isinstance(patch, str) or len(patch) > 24000:
                return "review", "Presentation-associated path, but its changed behavior could not be scoped."
            changed = "\n".join(
                line[1:]
                for line in patch.splitlines()
                if line[:1] in {"+", "-"} and not line.startswith(("+++", "---"))
            )
            if re.search(
                r"trusted_(?:content_)?hash|bypass_hook_trust|allow_managed_hooks_only|"
                r"(?:set|update|toggle|enable|disable|trust)_(?!(?:style|fg|bg|width|height|layout)\b)[A-Za-z_]+\s*\(|AppEvent::|"
                r"self(?:\.[A-Za-z_]+)+\s*=",
                changed,
            ) or any(line.startswith("-") and "#[cfg(test)]" in line for line in patch.splitlines()):
                return "review", "UI changes may mutate hook policy/state; presentation scope cannot clear them."
        return "informational", rule["reason"]
    return "review", "Runtime or unrecognized hook-related surface needs applicability review."


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
        number, files, all_files, complete = row["number"], [], [], False
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
                patch = item.get("patch")
                if (
                    not matches
                    and isinstance(patch, str)
                    and (
                        len(patch) > 24000
                        or re.search(
                            PATCH_REFERENCES[manifest["connector"]],
                            "\n".join(
                                line[1:]
                                for line in patch.splitlines()
                                if line[:1] in {"+", "-"} and not line.startswith(("+++", "---"))
                            ),
                        )
                    )
                ):
                    # Keywords route review only. A patch is never a standalone
                    # source of a proven invariant fact or compatibility claim.
                    matches = [
                        {
                            "invariants": ["hook.event_delivery", "hook.registration", "hook.execution"],
                            "review_focus": "Inspect changed hook references outside the configured artifact paths.",
                        }
                    ]
                scope, reason = file_scope(manifest, path, item.get("patch"))
                if old_path != path and file_scope(manifest, old_path, item.get("patch"))[0] != "informational":
                    scope, reason = "review", "Renamed from an unscoped artifact; do not lose the previous dependency."
                if not matches and scope == "review" and path not in watched:
                    scope, reason = (
                        "unmatched",
                        "No configured dependency matched; this is not connector-safety evidence.",
                    )
                all_files.append({"path": path, "scope": scope, "reason": reason})
                if matches and (path not in watched or old_path != path):
                    files.append(
                        {
                            "path": path,
                            "invariants": sorted({key for match in matches for key in match["invariants"]}),
                            "review_focus": sorted({match["review_focus"] for match in matches}),
                            "scope": scope,
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
                "file_inventory": all_files,
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
        file_inventory = pr.get("file_inventory", [])
        if not isinstance(files, list) or not isinstance(file_inventory, list) or len(file_inventory) > 1000:
            raise ValueError("invalid PR file inventory")
        if any(
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or item.get("scope") not in {"review", "informational", "unmatched"}
            for item in file_inventory
        ):
            raise ValueError("invalid PR file scope")
        active = [item for item in files if item.get("scope") != "informational"]
        if files or file_inventory:
            selected = sorted({key for item in active for key in item["invariants"]})
            checks = invariants.evaluate(
                provider.catalog,
                provider.local(),
                [],
                selected=selected,
                transport=provider.transport,
                texts=provider.texts,
            )
            text = pr["title"] + "\n" + "\n".join(item["path"] for item in file_inventory or files)
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
                    "decision": "review_required" if active else "observed",
                    "impact": "unknown" if active else "none",
                    "analysis_status": "unwatched_pr_artifact" if active else "informational_scope",
                    "artifact_classes": ["pr_inventory_gap"],
                    "risk_hints": ["coverage"],
                    "invariants": checks,
                    "local_artifacts": sorted({ref["artifact"] for check in checks for ref in check["local_evidence"]}),
                    "recommended_tests": [],
                    "unknowns": [
                        "Hook-related files changed outside the deterministic watchlist; review is needed."
                        if active
                        else "Informational routing only: no connector action was established. "
                        "Unmatched files and unchanged watched artifacts do not prove compatibility."
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
        "unmatched_files": sum(item.get("scope") == "unmatched" for pr in prs for item in pr.get("file_inventory", [])),
        "scope": "Up to 300 updated closed PRs; ten merged PRs per batch; initial latest ten only.",
    }
