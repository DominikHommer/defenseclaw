from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "docs-site/content/docs/enterprise/mdm/intune-tenant.mdx"


def test_macos_identity_row_stays_inside_the_table() -> None:
    page = PAGE.read_text(encoding="utf-8")
    section = page.split("## Identity through Intune", 1)[1].split("## ", 1)[0]
    rows = section.splitlines()
    linux = next(i for i, row in enumerate(rows) if row.startswith("| Linux, enrolled"))
    assert rows[linux + 1].startswith("| macOS, enrolled")
    assert "For that Linux pattern" in "\n".join(rows[linux + 2:])
