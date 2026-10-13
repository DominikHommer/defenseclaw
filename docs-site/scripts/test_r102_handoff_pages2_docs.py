"""Regression checks for round 1.0.2 handoff text on lane D pages."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(path):
    return (DOCS / path).read_text()


class R102HandoffPages2DocsTest(unittest.TestCase):
    def test_fg08_update_keeps_running_sessions_enforced(self):
        section = page("enterprise/tetragon.mdx").split(
            "5. **Restart agent sessions after enforce starts.**", 1
        )[1].split("The controls compile", 1)[0]
        self.assertIn("old controls policy\n   stays loaded and enforcing", section)
        self.assertNotIn("A planned follow-up", section)

    def test_fg08_predate_troubleshooting_excludes_self_update(self):
        tetragon = page("enterprise/tetragon.mdx")
        table = page("enterprise/troubleshooting.mdx")
        self.assertIn("enforce turned on or Tetragon restarted", tetragon)
        row = next(line for line in table.splitlines() if line.startswith("| `kernel_sessions_predate_controls`"))
        self.assertIn("old controls policy enforcing", row)
        self.assertNotIn("after an agent's own update", row)

    def test_fg08_limit_keeps_old_controls(self):
        section = page("enterprise/tetragon.mdx").split("## Reference", 1)[1]
        self.assertIn("old controls policy enforcing", section)
        self.assertNotIn("A planned follow-up", section)

    def test_fg08_lifecycle_retains_old_policy(self):
        row = next(line for line in page("enterprise/tetragon.mdx").splitlines()
                   if line.startswith("| An agent updates itself |"))
        self.assertIn("removed when the last one exits", row)
        self.assertNotIn("A planned follow-up", row)


if __name__ == "__main__":
    unittest.main()
