"""Pins for retained sandbox state in the managed uninstall documentation."""

import os
import unittest
from pathlib import Path


DOCS = Path(os.environ.get("R102_DELTA38_DOCS_ROOT", Path(__file__).resolve().parents[1] / "content/docs"))
LINUX = ("/var/lib/defenseclaw/sandbox", "/var/lib/defenseclaw/redaction-correlation.key")
MACOS = ("/opt/cisco/defenseclaw/runtime/sandbox", "/opt/cisco/defenseclaw/runtime/redaction-correlation.key")


class R102Delta38DocsTest(unittest.TestCase):
    def assert_kept_state(self, page, *paths):
        text = " ".join((DOCS / page).read_text().split())
        for path in paths:
            self.assertTrue(f"`{path}`" in text, f"{page} does not name {path}")
        for phrase in ("root-owned", "`ensure` adopts them", "`--purge`", "clean image"):
            self.assertTrue(phrase in text, f"{page} does not name {phrase}")
        for promise in ("The plain uninstall removes the machine state", "without it uninstall removes all of it"):
            self.assertFalse(promise in text, f"{page} still promises {promise}")

    def test_operations_image_template(self):
        self.assert_kept_state("enterprise/operations.mdx", *LINUX, *MACOS)

    def test_lifecycle_uninstall(self):
        self.assert_kept_state("enterprise/lifecycle.mdx", *LINUX, *MACOS)

    def test_linux_removal(self):
        self.assert_kept_state("enterprise/linux.mdx", *LINUX)

    def test_macos_removal(self):
        self.assert_kept_state("enterprise/macos.mdx", *MACOS)

    def test_mdm_removal(self):
        self.assert_kept_state("enterprise/mdm/index.mdx", *LINUX, *MACOS)

    def test_cli_uninstall(self):
        self.assert_kept_state("reference/cli.mdx", *LINUX, *MACOS)


if __name__ == "__main__":
    unittest.main()
