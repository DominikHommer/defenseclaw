"""Pin the 1.0.1 upgrade bridge for managed docker sandboxes (GAP-0587)."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs/enterprise"


def flat(name):
    return " ".join((DOCS / name).read_text().split())


class Delta42DocsTest(unittest.TestCase):
    def test_sandboxes_upgrade_from_101_keeps_kept_sandboxes(self):
        text = flat("sandboxes.mdx")
        bullet = text.split("- **Upgrade from 1.0.1 with the docker driver or the docker fallback.**", 1)[1]
        bullet = bullet.split("- **Roll back.**", 1)[0]
        for phrase in (
            "`gateway-docker-default-namespace.toml`",
            "while that user still keeps a sandbox there",
            "list, start, connect and pull as before, running or stopped",
            "the upgrade is a plain restart (\"pending restart\" while a sandbox runs), not a switch",
            "A user who never ran sandboxes moves straight to `defenseclaw-managed`",
            "once their last 1.0.1 sandbox is deleted",
            "The bridge lives in the setup's applied record, which an uninstall removes",
            "before an uninstall, pull the work you want to keep from the sandboxes kept under 1.0.1",
            "This is the 1.0.1 upgrade bridge; it is removed when 1.0.1 is out of support.",
        ):
            self.assertIn(phrase, bullet)
        for stale in ("cannot start, and OpenShell drops them", "before the upgrade", "pending switch"):
            self.assertNotIn(stale, bullet)

    def test_lifecycle_upgrade_names_the_bridge(self):
        text = flat("lifecycle.mdx")
        section = text.split("## Upgrade", 1)[1].split("### Windows", 1)[0]
        for phrase in (
            "keeps the sandboxes users kept under 1.0.1 working",
            "stays in OpenShell's `default` namespace until they keep no sandbox there",
            "nothing needs to be pulled before the upgrade",
            "the 1.0.1 upgrade bridge, removed when 1.0.1 is out of support",
        ):
            self.assertIn(phrase, section)


if __name__ == "__main__":
    unittest.main()
