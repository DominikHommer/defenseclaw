"""Regression checks for the 1.0.4 wave 3 G3 docs review fixes."""

import re
import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "content/docs"
REPO = Path(__file__).resolve().parents[2]


def page(name):
    return " ".join((DOCS / name).read_text().split())


class R104W3G3DocsTest(unittest.TestCase):
    def test_base_config_claim_names_only_what_the_packager_compares(self):
        packager = (REPO / "packaging/mdm/intune/windows/New-DefenseClawIntunePackage.ps1").read_text()
        self.assertIn("No other key is compared", packager)
        keys = re.search(r"foreach \(\$key in ((?:'[a-z_]+'(?:, )?)+)\)", packager)
        self.assertIsNotNone(keys, "packager hook-block key list not found")
        compared = re.findall(r"'([a-z_]+)'", keys.group(1))
        for name in ("enterprise/mdm/intune-windows.mdx", "enterprise/mdm/index.mdx"):
            text = page(name)
            self.assertNotIn("the packager checks this) so that window does not change what is blocked", text, name)
            self.assertIn("No other setting is compared", text, name)
            self.assertIn("such as `asset_policy:`, into the base config too", text, name)
            for key in compared:
                self.assertIn(f"`{key}:`", text, f"{name} does not name the compared {key}: block")


if __name__ == "__main__":
    unittest.main()
