"""Pin the 1.0.3 kept sandbox setup record and re-homed cleanup documentation (B-22)."""

import os
import unittest
from pathlib import Path


DOCS = Path(os.environ.get("R103_B22_DOCS_ROOT", Path(__file__).resolve().parents[1] / "content/docs"))


def page(name):
    return " ".join((DOCS / name).read_text().split())


class R103B22DocsTest(unittest.TestCase):
    def assert_phrases(self, name, *phrases):
        text = page(name)
        for phrase in phrases:
            with self.subTest(page=name, phrase=phrase):
                self.assertIn(phrase, text)

    def test_lifecycle_kept_setup_record_and_first_removal_purge(self):
        # rel-1-0-2:GAP-0622, GAP-0643 (1), GAP-0643 (5)
        self.assert_phrases(
            "enterprise/lifecycle.mdx",
            "The lifecycle directory then also keeps the root-only record of the sandbox setup those sandboxes were made under (`openshell-state.kept.json`)",
            "Purge in the first removal: a purge runs the deployment's own binary",
            "install the package or payload again and purge, or delete",
            "A purge also deletes each enrolled account's sandboxes and any sandbox work not pulled yet",
            "the recorded home of a removed or re-homed account is gone (nothing is left to remove)",
        )

    def test_mdm_and_jamf_purge_in_the_first_removal(self):
        # rel-1-0-2:GAP-0643 (1), (5)
        self.assert_phrases(
            "enterprise/mdm/index.mdx",
            "Use `--purge` for a clean image, in the first removal",
            "a purge after a plain removal finds nothing to run and exits `0` with that state still there",
        )
        self.assert_phrases("enterprise/mdm/jamf.mdx", "set `DC_PURGE=1` in the script's settings block in the first removal")

    def test_operations_clone_purges_and_lists_the_key(self):
        # rel-1-0-2:GAP-0643 (2)
        self.assert_phrases(
            "enterprise/operations.mdx",
            "the gateway's per-machine `redaction-correlation.key` and sandbox registration store, if an account on the template kept sandboxes",
            "Reinstall: uninstall with `--purge`, then install the same package or payload again",
            "a plain uninstall keeps that key on a clone whose accounts kept sandboxes",
            "A purge also deletes each enrolled account's `~/.defenseclaw`, its sandboxes and any sandbox work not pulled yet",
        )
        self.assertNotIn("if the template ever held sandboxes", page("enterprise/operations.mdx"))

    def test_cli_keep_state_and_purge_rows(self):
        # rel-1-0-2:GAP-0643 (3), GAP-0623
        text = page("reference/cli.mdx")
        row = text.split("| `--keep-state` | uninstall |", 1)[1].split("|", 1)[0]
        self.assertNotIn("lifecycle state", row)
        self.assertIn("The deployment record goes either way", row)
        self.assert_phrases("reference/cli.mdx", "with the root-only record of the sandbox setup they were made under", "Run it in the first removal: it needs the deployment's binaries")

    def test_linux_apt_purge_names_kept_sandboxes(self):
        # rel-1-0-2:GAP-0643 (5)
        self.assert_phrases("enterprise/linux.mdx", "The sandboxes the accounts kept in their homes are no longer known to a later install")

    def test_enrollment_rehome_shapes(self):
        # rel-1-0-2:GAP-0632, GAP-0633, GAP-0642
        self.assert_phrases(
            "enterprise/enrollment.mdx",
            "A home moved by copying it and then emptying the old folder counts as moved",
            "An agent config that is a symlink to a file in the same home is checked through the link",
            "Uninstall runs this cleanup also when a `targets.yaml` row still names the re-homed account",
        )


if __name__ == "__main__":
    unittest.main()
