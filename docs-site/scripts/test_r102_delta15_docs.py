"""Regression checks for the round 1.0.2 DELTA-15 docs (GAP-0172, GAP-0505, GAP-0510)."""

import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(path):
    return " ".join((DOCS / path).read_text().split())


class R102Delta15DocsTest(unittest.TestCase):
    def test_live_fields_reach_the_next_connection(self):
        text = page("enterprise/sandboxes.mdx")
        # gateway/sandbox_daemon_policy_fresh.go confirmEgressPolicy, sandboxEgressPolicyChanging.
        self.assertIn("decides each new connection with the policy the managed gateway confirmed for it within the last second", text)
        self.assertIn("your organization changed this sandbox's policy and DefenseClaw could not confirm the new one yet; try again in a moment", text)
        self.assertNotIn("takes the changed policy on its next relayed hook call", text)

    def test_account_outage_refusal_matches_the_cli(self):
        text = page("enterprise/sandboxes.mdx")
        # openshell/sandboxcli/managed_errors.go accountOutage.
        self.assertIn("Your account can't be looked up on this computer right now. Try again in a moment.", text)
        self.assertIn("This isn't your organization's sandbox policy.", text)
        self.assertIn("A slow or failed group lookup never refuses a create or a hook.", text)
        self.assertNotIn("A slow or failed lookup never refuses a create", text)

    def test_locked_pack_must_be_copy(self):
        text = page("enterprise/sandboxes.mdx")
        # config/openshell_tighten.go validateLockedSandboxPack.
        self.assertIn("`openshell.admin.locked: [pack]` makes the required pack of every sandbox", text)
        self.assertIn("set `workspace.mode: copy` in the pack", text)


if __name__ == "__main__":
    unittest.main()
