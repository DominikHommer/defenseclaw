# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Keep links valid when the feature's contributor documentation is moved."""

import re
import unittest

from scripts.connector_delta import monitor


class DocumentationTests(unittest.TestCase):
    def test_relative_document_links_resolve_inside_checkout(self):
        documents = [monitor.CONFIG / "README.md", *sorted((monitor.CONFIG / "docs").glob("*.md"))]
        for document in documents:
            for target in re.findall(r"\]\(([^)]+)\)", document.read_text(encoding="utf-8")):
                if "://" in target or target.startswith("#"):
                    continue
                target = target.split("#", 1)[0]
                resolved = (document.parent / target).resolve()
                with self.subTest(document=document.name, target=target):
                    self.assertTrue(resolved.is_relative_to(monitor.ROOT))
                    self.assertTrue(resolved.is_file())


if __name__ == "__main__":
    unittest.main()
