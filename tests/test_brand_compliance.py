"""Brand compliance guard — no competitor names in public copy."""

from __future__ import annotations

from tools.check_brand_compliance import main


def test_brand_compliance_passes() -> None:
    assert main() == 0


def test_visual_brand_check_reads_split_svg_wordmarks(tmp_path, monkeypatch, capsys) -> None:
    from tools import check_brand_compliance

    asset = tmp_path / "hero.svg"
    asset.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg"><title>GRC Lake</title><text>Trust<tspan>Ops</tspan></text></svg>'
    )
    monkeypatch.setattr(check_brand_compliance, "ROOT", tmp_path)
    monkeypatch.setattr(check_brand_compliance, "SCAN_ROOTS", (asset,))
    assert check_brand_compliance.main() == 1
    assert "retired visual brand 'TrustOps'" in capsys.readouterr().out

    asset.write_text(asset.read_text().replace("Trust<tspan>Ops", "GRC <tspan>Lake"))
    assert check_brand_compliance.main() == 0


def test_repository_owner_is_allowed_without_allowing_retired_product_copy(tmp_path, monkeypatch, capsys) -> None:
    from tools import check_brand_compliance

    owner = "ko" + "da-ai-studio"
    asset = tmp_path / "release.md"
    monkeypatch.setattr(check_brand_compliance, "ROOT", tmp_path)
    monkeypatch.setattr(check_brand_compliance, "SCAN_ROOTS", (asset,))
    asset.write_text(f"Owner: `{owner}`\nRepo: `{owner}/grc-lake`\nImage: ghcr.io/{owner}/grc-lake\n")
    assert check_brand_compliance.main() == 0

    for text in ("Ko" + "da product", f"{owner}-other", f"other-{owner}"):
        asset.write_text(f"Owner: {owner}\n{text}\n")
        assert check_brand_compliance.main() == 1
        assert "retired brand" in capsys.readouterr().out


def test_repository_owner_does_not_exempt_visual_wordmarks(tmp_path, monkeypatch, capsys) -> None:
    from tools import check_brand_compliance

    asset = tmp_path / "hero.svg"
    asset.write_text("<svg><text>ko" + "da-ai-studio</text></svg>")
    monkeypatch.setattr(check_brand_compliance, "ROOT", tmp_path)
    monkeypatch.setattr(check_brand_compliance, "SCAN_ROOTS", (asset,))
    assert check_brand_compliance.main() == 1
    assert "retired visual brand" in capsys.readouterr().out
