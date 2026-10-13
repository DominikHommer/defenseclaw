"""Regression checks for round 1.0.2 batch DELTA-13: the docker group and policy privacy."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs/enterprise"


def page(name):
    return " ".join((DOCS / name).read_text().split())


class R102Delta13DocsTest(unittest.TestCase):
    def test_gap_0498_prerequisites_say_docker_reads_the_admin_policy(self):
        text = page("sandboxes.mdx")
        self.assertIn("A member of `docker` can read every file on the host that root can, including "
                      "the administrator policy in `/etc/defenseclaw/config.yaml`", text)
        self.assertIn("Put only the accounts that run sandboxes in `docker`", text)
        self.assertIn("a destination header that carries a credential belongs in `{credential: NAME}` or `{env: NAME}`", text)
        self.assertNotIn("put only the sandbox user in `docker`.", text)

    def test_gap_0498_privacy_names_the_docker_group_residual(self):
        text = page("sandboxes.mdx")
        self.assertIn("**Residual: Docker group members.**", text)
        self.assertIn("the privacy rules above hold only for accounts outside the group", text)
        self.assertIn("On Linux this holds only for accounts outside the `docker` group", text)
        self.assertIn("a **Docker access** warning", text)

    def test_gap_0498_verify_code_counts_without_names(self):
        text = page("sandboxes.mdx")
        self.assertIn("| `docker_group_members` | How many enrolled accounts are in the `docker` group (Linux)", text)
        self.assertIn("A number, never names", text)

    def test_gap_0498_linux_page_warns_and_links(self):
        text = page("linux.mdx")
        self.assertIn("Membership in `docker` is root-equivalent: a member can read the administrator policy", text)
        self.assertIn("its agent images are built in Docker, so it needs the `docker` group too", text)
        self.assertIn("(/docs/enterprise/sandboxes#what-users-see)", text)


if __name__ == "__main__":
    unittest.main()
