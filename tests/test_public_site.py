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
    styles = (SITE / "styles.css").read_text(encoding="utf-8")
    manifest = json.loads((SITE / "demo-data" / "manifest.json").read_bytes())
    nginx = (ROOT / "deploy" / "nginx-qualityci.conf.example").read_text(encoding="utf-8")
    nginx_limits = (ROOT / "deploy" / "nginx-qualityci-limits.conf.example").read_text(encoding="utf-8")
    gateway_unit = (ROOT / "deploy" / "qualityci-leader-gateway.service.example").read_text(encoding="utf-8")
    pages_workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")
    experience = (SITE / "experience.html").read_text(encoding="utf-8")
    experience_app = (SITE / "experience.js").read_text(encoding="utf-8")
    experience_styles = (SITE / "experience.css").read_text(encoding="utf-8")

    assert "QualityCI｜工业质量回归基础设施" in index
    assert "静态契约示意" in index
    assert "预计算静态回放" not in index
    assert 'role="tabpanel"' in index
    assert 'aria-controls="demo-panel"' in index
    assert 'property="og:image:width" content="1200"' in index
    assert 'property="og:image:height" content="630"' in index
    assert "https://github.com/muchensu77-create/qualityci" in index
    assert "待授权" not in index
    assert "摘要哈希待校验" in index
    assert "SHA-256 verified" not in index
    assert 'data-regression-sequence' in index
    assert 'data-sequence-phase="0"' in index
    assert 'data-sequence-phase="3"' in index
    assert 'data-case-summary' in index
    assert 'data-case-detail' in index
    assert 'data-open-evidence' in index
    assert index.count('class="deck-page') == 4
    assert 'data-page="overview"' in index
    assert 'data-page="method"' in index
    assert 'data-page="case"' in index
    assert 'data-page="proof"' in index
    assert 'data-page-prev' in index
    assert 'data-page-next' in index
    assert 'data-page-progress' in index
    assert 'data-page-announcer' in index
    assert 'class="nojs-scenarios"' in index
    assert "A08_SOURCE_PACK_REQUIRED" in index
    assert "READY_FOR_HUMAN_RELEASE_REVIEW" in index
    assert "一次工程变更。" not in index
    assert "FangSong" in styles
    assert "Baskerville" in styles
    assert "#1769e0" not in styles.lower()
    assert ".hero-boundaries li::before" not in styles
    assert "html:not(.js) .site-header" in styles
    assert ".js .deck-footer" in styles
    assert "/api/" not in app
    assert 'selectScenario("conflict", initialTab)' in app
    assert 'setHashStatus("本次浏览器校验已匹配", "matched")' in app
    assert 'crypto.subtle.digest("SHA-256", raw)' in app
    assert "setSequencePhase(0)" in app
    assert "sequenceStage.dataset.phase" in app
    assert 'document.startViewTransition' in app
    assert 'activeViewTransition?.skipTransition()' in app
    assert 'transition.finished.finally' in app
    assert 'document.querySelector(".skip-link")?.addEventListener' in app
    assert "pendingPageKey ?? currentPageKey" in app
    assert "storyTransitionOwner === transition" in app
    assert "EXPECTED_SCENARIOS" in app
    assert "gsap" not in app.lower()
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
    assert 'href="/qualityci/styles.css"' in not_found
    assert 'href="/qualityci/"' in not_found
    assert 'href="/styles.css"' not in not_found
    assert 'href="/"' not in not_found
    assert (SITE / ".nojekyll").is_file()
    assert "contents: read" in pages_workflow
    assert "pages: write" in pages_workflow
    assert "id-token: write" in pages_workflow
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in pages_workflow
    assert "actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9" in pages_workflow
    assert "actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128" in pages_workflow
    assert "path: site" in pages_workflow
    assert "include-hidden-files: true" in pages_workflow
    assert "persist-credentials: false" in pages_workflow
    assert "location = /api" in nginx
    assert "location ^~ /api/" in nginx
    assert "location = /api/v1/leader-answer" in nginx
    assert "proxy_pass http://127.0.0.1:8789" in nginx
    assert nginx.count("proxy_pass") == 1
    assert "client_max_body_size 1k" in nginx
    assert "access_log off" in nginx
    assert "qualityci_leader_per_ip" in nginx_limits
    assert "qualityci_leader_global" in nginx_limits
    assert "DynamicUser=yes" in gateway_unit
    assert "NoNewPrivileges=yes" in gateway_unit
    assert "ProtectSystem=strict" in gateway_unit
    assert "IPAddressDeny=any" in gateway_unit
    assert "IPAddressAllow=localhost" in gateway_unit
    assert 'X-Frame-Options "DENY"' in nginx
    assert "Strict-Transport-Security" in nginx
    assert "include /etc/nginx/mime.types" in nginx
    assert "领导体验" in experience
    assert "无自由文本／无上传" in experience
    assert 'type="file"' not in experience
    assert "<textarea" not in experience
    assert "leader-experience.v1" in experience_app
    assert 'const ENDPOINT = "/api/v1/leader-answer"' in experience_app
    assert 'const IS_STATIC_MIRROR = window.location.hostname === "muchensu77-create.github.io"' in experience_app
    assert "if (IS_STATIC_MIRROR)" in experience_app
    assert "GitHub Pages 静态镜像／模型服务未接入" in experience_app
    assert "release_decision" in experience_app
    assert "blocking_reason" in experience_app
    assert "required_evidence" in experience_app
    assert "next_action" in experience_app
    assert "static_fallback" in experience_app
    assert "SOURCE_ROOTED_RUN／trusted true" in experience_app
    assert "PASS／BOUND_RAW_SOURCE_CASE" in experience_app
    assert "activeDeadline?.abort()" in experience_app
    assert experience_app.rstrip().endswith("requestAnswer();")
    assert "credentials: \"omit\"" in experience_app
    assert "redirect: \"error\"" in experience_app
    assert "localStorage" not in experience_app
    assert "sessionStorage" not in experience_app
    assert "document.cookie" not in experience_app
    assert "innerHTML" not in experience_app
    assert "textContent" in experience_app
    assert "gsap" not in experience_app.lower()
    assert "FangSong" in experience_styles
    assert "Baskerville" in experience_styles
    assert "#1769e0" not in experience_styles.lower()
    assert "https://qualityci.com/experience.html" in (SITE / "sitemap.xml").read_text(encoding="utf-8")

    asset_notice = (SITE / "ASSET_NOTICE.md").read_text(encoding="utf-8")
    assert hashlib.sha256((SITE / "og.png").read_bytes()).hexdigest() in asset_notice

    parser = _AssetParser()
    parser.feed(index)
    parser.feed(experience)
    for value in parser.assets:
        if value.startswith(("#", "https://", "mailto:")):
            continue
        relative = value.split("#", 1)[0].split("?", 1)[0]
        target = (SITE / relative).resolve()
        assert target == SITE.resolve() or SITE.resolve() in target.parents
        assert target.is_file()
