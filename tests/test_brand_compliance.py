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
