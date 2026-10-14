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

    def test_lifecycle_registrations_left_warning_and_error(self):
        text = " ".join((DOCS / "enterprise/lifecycle.mdx").read_text().split())
        for phrase in (
            "Registrations left, warning",
            "Registrations left, error",
            "home is unavailable",
            "old home cannot be trusted",
            "uninstall warns with `per_user_hooks_remaining` and goes on",
            "failures report `per_user_hooks_remaining`",
            "stop uninstall before removing the binaries",
            "/docs/enterprise/troubleshooting#warnings",
        ):
            self.assertTrue(phrase in text, f"lifecycle.mdx omits {phrase}")

    def assert_agent_settings_notice(self, page):
        text = " ".join((DOCS / page).read_text().split())
        for phrase in (
            "`status` and `verify` also warn with `agent_settings_not_restored`",
            "Hermes `config.yaml` without a copy",
            "Devin `config.json` from its last good copy",
            "settings may be missing or older",
            "not make `security_complete` false or `verify` fail",
        ):
            self.assertTrue(phrase in text, f"{page} omits {phrase}")

    def test_linux_agent_settings_notice(self):
        self.assert_agent_settings_notice("enterprise/linux.mdx")

    def test_macos_agent_settings_notice(self):
        self.assert_agent_settings_notice("enterprise/macos.mdx")


if __name__ == "__main__":
    unittest.main()
