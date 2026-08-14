from __future__ import annotations

import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


class _AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if key in {"href", "src"} and value:
                self.assets.append(value)


def test_public_site_is_static_synthetic_and_self_contained() -> None:
    index = (SITE / "index.html").read_text(encoding="utf-8")
    app = (SITE / "app.js").read_text(encoding="utf-8")
    manifest = json.loads((SITE / "demo-data" / "manifest.json").read_bytes())
    nginx = (ROOT / "deploy" / "nginx-qualityci.conf.example").read_text(encoding="utf-8")

    assert "QualityCI｜工业质量回归基础设施" in index
    assert "静态契约示意" in index
    assert "预计算静态回放" not in index
    assert 'role="tabpanel"' in index
    assert 'aria-controls="demo-panel"' in index
    assert 'property="og:image:width" content="1200"' in index
    assert 'property="og:image:height" content="630"' in index
    assert "https://github.com/muchensu77-create/qualityci" in index
    assert "待授权" not in index
    assert "/api/" not in app
    assert 'selectScenario("conflict", initialTab)' in app
    assert manifest["synthetic"] is True
    assert manifest["contract_version"] == "qualityci-static-walkthrough-0.1"
    assert manifest["runtime_mode"] == "STATIC_CONTRACT_WALKTHROUGH"
    assert manifest["source_profile"] == "PUBLIC_ENTRY_FIELD_SUMMARY"
    assert manifest["raw_runtime_log"] is False
    assert manifest["ruleset_version"] == "qci-rules-0.6.0"

    for scenario_id, filename in manifest["scenarios"].items():
        raw = (SITE / "demo-data" / filename).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == manifest["scenario_sha256"][scenario_id]
        scenario = json.loads(raw)
        assert scenario["scenario_id"] == scenario_id
        assert scenario["synthetic"] is True

    assert json.loads((SITE / "demo-data" / manifest["scenarios"]["conflict"]).read_bytes())["result"] == {
        "mode": "RUN_EVALUATION_UNBOUND",
        "trusted": False,
        "admission": "BLOCKED",
        "overall_status": "CONTRADICTED",
        "rules": 7,
        "pass": 4,
        "contradicted": 3,
    }
    assert json.loads((SITE / "demo-data" / manifest["scenarios"]["blocked"]).read_bytes())["result"] == {
        "http_status": 409,
        "status": "BLOCKED",
        "approval_mode": "SOURCE_ROOTED_RAW_MATERIAL_REQUIRED",
        "error": "A08_SOURCE_PACK_REQUIRED",
    }
    ready = json.loads((SITE / "demo-data" / manifest["scenarios"]["ready"]).read_bytes())["result"]
    assert ready["trusted"] is True
    assert ready["team_state"] == "READY_FOR_HUMAN_RELEASE_REVIEW"

    assert (SITE / "robots.txt").read_text(encoding="utf-8") == (
        "User-agent: *\nAllow: /\n\nSitemap: https://qualityci.com/sitemap.xml\n"
    )
    not_found = (SITE / "404.html").read_text(encoding="utf-8")
    assert 'href="/styles.css"' in not_found
    assert 'href="/"' in not_found
    assert "location = /api" in nginx
    assert "location ^~ /api/" in nginx
    assert 'X-Frame-Options "DENY"' in nginx
    assert "Strict-Transport-Security" in nginx
    assert "include /etc/nginx/mime.types" in nginx
    assert "proxy_pass" not in nginx

    asset_notice = (SITE / "ASSET_NOTICE.md").read_text(encoding="utf-8")
    assert hashlib.sha256((SITE / "og.png").read_bytes()).hexdigest() in asset_notice

    parser = _AssetParser()
    parser.feed(index)
    for value in parser.assets:
        if value.startswith(("#", "https://", "mailto:")):
            continue
        relative = value.split("#", 1)[0].split("?", 1)[0]
        target = (SITE / relative).resolve()
        assert target == SITE.resolve() or SITE.resolve() in target.parents
        assert target.is_file()
