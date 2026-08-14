from __future__ import annotations

from datetime import date, datetime
import json
import math
from typing import Any, Callable

from .controlled_references import (
    _ControlledReferenceContext,
    _is_sealed_reference_context,
)
from .loader import document_by_type, normalized_identity, relationship_key
from .models import CheckStatus, EvidenceRef, Finding, ImpactPlan
from .validation_evidence import (
    _ValidationEvidenceContext,
    _is_sealed_validation_context,
)

RULESET_VERSION = "qci-rules-0.6.0"


def _stable_excerpt(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
            allow_nan=False,
        )
    return str(value)


def _evidence(doc: dict[str, Any], locator: str, excerpt: Any) -> EvidenceRef:
    return EvidenceRef(
        document_id=doc["document_id"],
        revision=doc.get("revision", "UNKNOWN"),
        locator=locator,
        excerpt=_stable_excerpt(excerpt),
        source_hash=doc.get("source_hash", ""),
    )


def _event_evidence(event: dict[str, Any], locator: str, excerpt: Any) -> EvidenceRef:
    return EvidenceRef(
        document_id="CHANGE_EVENT",
        revision=event.get("revision", "UNKNOWN"),
        locator=locator,
        excerpt=_stable_excerpt(excerpt),
    )


def _case_evidence(case: dict[str, Any], locator: str, excerpt: Any) -> EvidenceRef:
    return EvidenceRef(
        document_id="CASE_INPUT",
        revision="1",
        locator=locator,
        excerpt=_stable_excerpt(excerpt),
    )


def _finding(
    rule_id: str,
    title: str,
    status: CheckStatus,
    summary: str,
    evidence: list[EvidenceRef] | None = None,
    severity: str = "MEDIUM",
    remediation: str = "",
    acceptance: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        status=status,
        severity=severity,
        summary=summary,
        evidence=tuple(evidence or []),
        remediation=remediation,
        acceptance_conditions=acceptance,
    )


def _pair_label(pair: tuple[str, str]) -> str:
    return f"({pair[0]}, {pair[1]})"


def _relationship_excerpt(item: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "process_step_id",
        "characteristic_id",
        "failure_mode_id",
        "control_id",
    )
    return {key: item[key] for key in keys if key in item}


def _relationship_evidence(doc: dict[str, Any], item: dict[str, Any]) -> EvidenceRef:
    return _evidence(
        doc,
        item.get("locator", "RELATION_LOCATOR_MISSING"),
        _relationship_excerpt(item),
    )


def _missing_relationship_evidence(
    doc: dict[str, Any], collection: str, pair: tuple[str, str]
) -> EvidenceRef:
    return _evidence(
        doc,
        (
            f"fields.{collection}[process_step_id={pair[0]}]"
            f"[characteristic_id={pair[1]}]"
        ),
        {
            "expected_pair": {
                "process_step_id": pair[0],
                "characteristic_id": pair[1],
            },
            "status": "MISSING_EXPECTED_RELATIONSHIP",
        },
    )


def _event_relationship_evidence(
    event: dict[str, Any], pair: tuple[str, str]
) -> EvidenceRef:
    return _event_evidence(
        event,
        (
            f"affected_links[process_step_id={pair[0]}]"
            f"[characteristic_id={pair[1]}]"
        ),
        {"process_step_id": pair[0], "characteristic_id": pair[1]},
    )


def _scope_relationships_complete(plan: ImpactPlan) -> bool:
    if not plan.affected_links:
        return False
    linked_characteristics = {
        normalized_identity(characteristic_id)
        for _, characteristic_id in plan.affected_links
    }
    return all(
        normalized_identity(characteristic_id) in linked_characteristics
        for characteristic_id in plan.affected_characteristics
    )


def _characteristics(
    doc: dict[str, Any] | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    if not doc:
        return {}
    return {
        relationship_key(item["process_step_id"], item["characteristic_id"]): item
        for item in doc.get("fields", {}).get("characteristics", [])
        if isinstance(item.get("process_step_id"), str)
    }


def _risks(
    doc: dict[str, Any] | None,
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    if not doc:
        return index
    for risk in doc.get("fields", {}).get("risks", []):
        if not isinstance(risk.get("process_step_id"), str):
            continue
        key = relationship_key(risk["process_step_id"], risk["characteristic_id"])
        index.setdefault(key, []).append(risk)
    return index


def _relationship_candidates(
    indexes: tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]],
    pair: tuple[str, str],
) -> list[dict[str, Any]]:
    expected = relationship_key(*pair)
    candidates: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in (*indexes[0].get(expected[0], []), *indexes[1].get(expected[1], [])):
        identity = id(item)
        if identity in seen:
            continue
        seen.add(identity)
        candidates.append(item)
        if len(candidates) == 3:
            break
    return candidates


def _relationship_candidate_indexes(
    items: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    by_step: dict[str, list[dict[str, Any]]] = {}
    by_characteristic: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        if not isinstance(item.get("process_step_id"), str):
            continue
        step, characteristic = relationship_key(
            item["process_step_id"], item["characteristic_id"]
        )
        by_step.setdefault(step, []).append(item)
        by_characteristic.setdefault(characteristic, []).append(item)
    return by_step, by_characteristic


def _legacy_unbound_evidence(
    case: dict[str, Any],
    documents: list[tuple[dict[str, Any], tuple[str, ...]]],
) -> list[EvidenceRef]:
    if "relationship_migration" not in case:
        return []
    evidence: list[EvidenceRef] = []
    for document, collections in documents:
        for collection in collections:
            for item in document.get("fields", {}).get(collection, []):
                missing = ["process_step_id"] if not item.get("process_step_id") else []
                if (
                    document.get("document_type") == "CONTROL_PLAN"
                    and collection == "characteristics"
                    and not item.get("control_id")
                ):
                    missing.append("control_id")
                if missing:
                    evidence.append(
                        _evidence(
                            document,
                            item.get("locator", f"fields.{collection}"),
                            {
                                "status": "LEGACY_RELATIONSHIP_UNPROVEN",
                                "missing": missing,
                                "characteristic_id": item.get("characteristic_id"),
                                "failure_mode_id": item.get("failure_mode_id"),
                            },
                        )
                    )
    return evidence


def _spec_tuple(item: dict[str, Any]) -> tuple[Any, ...] | None:
    spec = item.get("specification")
    if not isinstance(spec, dict):
        return None
    keys = ("target", "minimum", "maximum", "unit")
    if any(key not in spec for key in keys):
        return None
    target, minimum, maximum, unit = (spec[key] for key in keys)
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        for value in (target, minimum, maximum)
    ):
        return None
    if not isinstance(unit, str) or not unit.strip() or not minimum <= target <= maximum:
        return None
    return target, minimum, maximum, unit


def rule_process_coverage(case: dict[str, Any], plan: ImpactPlan) -> Finding:
    process_flow = document_by_type(case, "PROCESS_FLOW")
    pfmea = document_by_type(case, "PFMEA")
    control = document_by_type(case, "CONTROL_PLAN")
    if not process_flow or not pfmea or not control or not plan.affected_process_steps:
        evidence = [
            _event_evidence(case["event"], "affected_process_steps", list(plan.affected_process_steps)),
            _case_evidence(case, "documents[*].document_type", [doc.get("document_type") for doc in case["documents"]]),
        ]
        return _finding(
            "QCI-R001", "受影响工序覆盖", CheckStatus.UNVERIFIABLE,
            "缺少过程流程图、PFMEA、控制计划或受影响工序清单。", evidence,
        )
    process_flow_steps = set(process_flow.get("fields", {}).get("process_steps", []))
    pfmea_steps = set(pfmea.get("fields", {}).get("process_steps", []))
    control_steps = set(control.get("fields", {}).get("process_steps", []))
    normalized_step_sets = [
        {normalized_identity(step) for step in values}
        for values in (process_flow_steps, pfmea_steps, control_steps)
    ]
    missing = [
        step
        for step in plan.affected_process_steps
        if any(normalized_identity(step) not in values for values in normalized_step_sets)
    ]
    evidence = [
        _evidence(process_flow, "fields.process_steps", sorted(process_flow_steps)),
        _evidence(pfmea, "fields.process_steps", sorted(pfmea_steps)),
        _evidence(control, "fields.process_steps", sorted(control_steps)),
    ]
    if missing:
        return _finding(
            "QCI-R001", "受影响工序覆盖", CheckStatus.CONTRADICTED,
            f"工序未同时进入过程流程图、PFMEA与控制计划：{', '.join(missing)}。", evidence, "HIGH",
            "补充缺失工序及其流程、风险与控制映射。",
            ("过程流程图、PFMEA与控制计划均包含全部受影响工序",),
        )
    if not _scope_relationships_complete(plan):
        return _finding(
            "QCI-R001",
            "受影响工序覆盖",
            CheckStatus.UNVERIFIABLE,
            "受影响特性缺少确定的工序—特性关系，不能从独立集合推断。",
            [
                _event_evidence(
                    case["event"],
                    "affected_links",
                    case["event"].get("affected_links", "FIELD_ABSENT"),
                )
            ],
            "HIGH",
            "为每个受影响特性声明显式affected_links关系。",
            ("每个受影响特性至少绑定一个明确工序",),
        )

    legacy_unbound = _legacy_unbound_evidence(
        case,
        [(pfmea, ("risks",)), (control, ("characteristics",))],
    )
    if legacy_unbound:
        return _finding(
            "QCI-R001",
            "受影响工序覆盖",
            CheckStatus.UNVERIFIABLE,
            "旧版文档行没有可定位的工序关系；事件scope不能替代文档证据。",
            legacy_unbound,
            "HIGH",
        )

    risk_index = _risks(pfmea)
    control_index = _characteristics(control)
    relation_evidence: list[EvidenceRef] = []
    relation_gaps: list[str] = []
    pfmea_items = pfmea.get("fields", {}).get("risks", [])
    control_items = control.get("fields", {}).get("characteristics", [])
    pfmea_candidate_indexes = _relationship_candidate_indexes(pfmea_items)
    control_candidate_indexes = _relationship_candidate_indexes(control_items)
    for pair in plan.affected_links:
        key = relationship_key(*pair)
        relation_evidence.append(_event_relationship_evidence(case["event"], pair))
        matching_risks = risk_index.get(key, [])
        control_item = control_index.get(key)
        if matching_risks:
            relation_evidence.extend(
                _relationship_evidence(pfmea, item) for item in matching_risks
            )
        else:
            relation_gaps.append(f"PFMEA:{_pair_label(pair)}")
            relation_evidence.append(
                _missing_relationship_evidence(pfmea, "risks", pair)
            )
            relation_evidence.extend(
                _relationship_evidence(pfmea, item)
                for item in _relationship_candidates(pfmea_candidate_indexes, pair)
            )
        if control_item:
            relation_evidence.append(_relationship_evidence(control, control_item))
        else:
            relation_gaps.append(f"CONTROL_PLAN:{_pair_label(pair)}")
            relation_evidence.append(
                _missing_relationship_evidence(control, "characteristics", pair)
            )
            relation_evidence.extend(
                _relationship_evidence(control, item)
                for item in _relationship_candidates(control_candidate_indexes, pair)
            )
    if relation_gaps:
        return _finding(
            "QCI-R001",
            "受影响工序覆盖",
            CheckStatus.CONTRADICTED,
            "缺少显式工序—特性承接关系：" + ", ".join(relation_gaps),
            evidence + relation_evidence,
            "HIGH",
            "在PFMEA与控制计划中补齐与事件affected_links完全一致的关系边。",
            ("每个affected_links pair均有PFMEA风险与控制计划控制项",),
        )
    return _finding(
        "QCI-R001", "受影响工序覆盖", CheckStatus.PASS,
        "受影响工序及显式工序—特性关系已由流程、风险与控制行承接。",
        evidence + relation_evidence,
        "LOW",
    )


def rule_spec_consistency(case: dict[str, Any], plan: ImpactPlan) -> Finding:
    docs = [document_by_type(case, kind) for kind in ("CONTROL_PLAN", "SOP", "INSPECTION_RECORD")]
    if any(doc is None for doc in docs) or not plan.affected_characteristics:
        evidence = [
            _event_evidence(case["event"], "affected_characteristics", list(plan.affected_characteristics)),
            _case_evidence(case, "documents[*].document_type", [doc.get("document_type") for doc in case["documents"]]),
        ]
        return _finding("QCI-R002", "跨文档规格一致性", CheckStatus.UNVERIFIABLE, "缺少控制计划、SOP、检验记录或受影响特性。", evidence)
    if not _scope_relationships_complete(plan):
        return _finding(
            "QCI-R002",
            "跨文档规格一致性",
            CheckStatus.UNVERIFIABLE,
            "缺少显式affected_links，不能确定应比较哪一道工序的同名特性。",
            [
                _event_evidence(
                    case["event"],
                    "affected_links",
                    case["event"].get("affected_links", "FIELD_ABSENT"),
                )
            ],
            "HIGH",
        )
    legacy_unbound = _legacy_unbound_evidence(
        case,
        [(doc, ("characteristics",)) for doc in docs if doc is not None],
    )
    if legacy_unbound:
        return _finding(
            "QCI-R002",
            "跨文档规格一致性",
            CheckStatus.UNVERIFIABLE,
            "旧版规格行没有显式工序关系，不能按pair比较。",
            legacy_unbound,
            "HIGH",
        )
    indexed_docs = [
        (
            doc,
            _characteristics(doc),
            _relationship_candidate_indexes(
                doc.get("fields", {}).get("characteristics", [])
            ),
        )
        for doc in docs
        if doc is not None
    ]
    evidence: list[EvidenceRef] = []
    missing: list[str] = []
    conflicts: list[str] = []
    misbound: list[str] = []
    for pair in plan.affected_links:
        values: dict[str, tuple[Any, ...]] = {}
        for doc, characteristic_index, candidate_indexes in indexed_docs:
            item = characteristic_index.get(relationship_key(*pair))
            spec = _spec_tuple(item) if item else None
            if spec is None:
                label = f"{doc['document_type']}:{_pair_label(pair)}"
                missing.append(label)
                if item is None:
                    evidence.append(
                        _missing_relationship_evidence(doc, "characteristics", pair)
                    )
                    candidates = _relationship_candidates(candidate_indexes, pair)
                    if candidates:
                        misbound.append(label)
                        evidence.extend(
                            _relationship_evidence(doc, candidate)
                            for candidate in candidates
                        )
                else:
                    evidence.append(
                        _evidence(
                            doc,
                            item.get("locator", "fields.characteristics"),
                            {
                                "pair": _relationship_excerpt(item),
                                "specification": item.get("specification", "FIELD_ABSENT"),
                                "status": "SPECIFICATION_INCOMPLETE_OR_INVALID",
                            },
                        )
                    )
                continue
            values[doc["document_type"]] = spec
            evidence.append(
                _evidence(
                    doc,
                    item.get("locator", "fields.characteristics"),
                    {"pair": _relationship_excerpt(item), "specification": spec},
                )
            )
        if len(set(values.values())) > 1:
            conflicts.append(f"{_pair_label(pair)}={values}")
    if conflicts:
        return _finding(
            "QCI-R002", "跨文档规格一致性", CheckStatus.CONTRADICTED,
            "发现规格或单位冲突：" + "; ".join(conflicts), evidence, "HIGH",
            "由工艺/质量负责人确认权威规格后，同步控制计划、SOP与检验准则。",
            ("三类文件规格和单位完全一致", "修订记录包含Owner与批准信息"),
        )
    if misbound:
        return _finding(
            "QCI-R002",
            "跨文档规格一致性",
            CheckStatus.CONTRADICTED,
            "同名特性绑定到错误工序：" + ", ".join(misbound),
            evidence,
            "HIGH",
            "按affected_links修正文档的工序—特性关系。",
            ("控制计划、SOP与检验记录均按同一pair提供规格",),
        )
    if missing:
        return _finding(
            "QCI-R002", "跨文档规格一致性", CheckStatus.UNVERIFIABLE,
            "缺少可比较规格：" + ", ".join(missing), evidence, "HIGH",
            "补齐缺失特性及其规格证据。", ("所有受影响特性在三类文件中均有可定位规格",),
        )
    return _finding("QCI-R002", "跨文档规格一致性", CheckStatus.PASS, "控制计划、SOP与检验记录中同一工序—特性pair的规格一致。", evidence, "LOW")


def rule_special_characteristic_control(case: dict[str, Any], plan: ImpactPlan) -> Finding:
    pfmea = document_by_type(case, "PFMEA")
    control = document_by_type(case, "CONTROL_PLAN")
    if not pfmea or not control:
        return _finding(
            "QCI-R003", "特殊特性控制覆盖", CheckStatus.UNVERIFIABLE, "缺少PFMEA或控制计划。",
            [_case_evidence(case, "documents[*].document_type", [doc.get("document_type") for doc in case["documents"]])],
        )
    if not _scope_relationships_complete(plan):
        return _finding(
            "QCI-R003",
            "特殊特性控制覆盖",
            CheckStatus.UNVERIFIABLE,
            "缺少显式affected_links，无法确定风险与控制的关系主体。",
            [
                _event_evidence(
                    case["event"],
                    "affected_links",
                    case["event"].get("affected_links", "FIELD_ABSENT"),
                )
            ],
            "HIGH",
        )
    legacy_unbound = _legacy_unbound_evidence(
        case,
        [(pfmea, ("risks",)), (control, ("characteristics",))],
    )
    if legacy_unbound:
        return _finding(
            "QCI-R003",
            "特殊特性控制覆盖",
            CheckStatus.UNVERIFIABLE,
            "旧版风险/控制行没有显式关系，不能从事件scope反推。",
            legacy_unbound,
            "HIGH",
        )
    control_chars = _characteristics(control)
    risks = pfmea.get("fields", {}).get("risks", [])
    risk_index = _risks(pfmea)
    risk_candidate_indexes = _relationship_candidate_indexes(risks)
    control_candidate_indexes = _relationship_candidate_indexes(
        control.get("fields", {}).get("characteristics", [])
    )
    missing_risk = [
        pair for pair in plan.affected_links if relationship_key(*pair) not in risk_index
    ]
    if missing_risk:
        evidence: list[EvidenceRef] = []
        explicit_misbindings = False
        for pair in missing_risk:
            evidence.append(_event_relationship_evidence(case["event"], pair))
            evidence.append(_missing_relationship_evidence(pfmea, "risks", pair))
            candidates = _relationship_candidates(risk_candidate_indexes, pair)
            explicit_misbindings = explicit_misbindings or bool(candidates)
            evidence.extend(
                _relationship_evidence(pfmea, item)
                for item in candidates
            )
        return _finding(
            "QCI-R003",
            "特殊特性控制覆盖",
            (
                CheckStatus.CONTRADICTED
                if explicit_misbindings
                else CheckStatus.UNVERIFIABLE
            ),
            (
                "受影响pair被绑定到错误工序或特性："
                if explicit_misbindings
                else "受影响pair缺少可定位PFMEA风险条目："
            )
            + ", ".join(_pair_label(pair) for pair in missing_risk),
            evidence,
            "HIGH",
            "在PFMEA中补充受影响工序—特性pair的可定位风险分析。",
            ("每个affected_links pair至少对应一条可定位PFMEA风险",),
        )
    gaps: list[str] = []
    evidence: list[EvidenceRef] = []
    for pair in plan.affected_links:
        key = relationship_key(*pair)
        pair_risks = risk_index[key]
        evidence.extend(_relationship_evidence(pfmea, risk) for risk in pair_risks)
        if not any(risk.get("special_characteristic") for risk in pair_risks):
            continue
        item = control_chars.get(key)
        if not item or not all(
            isinstance(item.get(field), str) and item[field].strip()
            for field in ("control_method", "frequency", "reaction_plan")
        ):
            gaps.append(_pair_label(pair))
            if item:
                evidence.append(_relationship_evidence(control, item))
            else:
                evidence.append(
                    _missing_relationship_evidence(control, "characteristics", pair)
                )
                evidence.extend(
                    _relationship_evidence(control, candidate)
                    for candidate in _relationship_candidates(
                        control_candidate_indexes, pair
                    )
                )
        else:
            evidence.append(
                _evidence(
                    control,
                    item.get("locator", "fields.characteristics"),
                    {
                        "pair": _relationship_excerpt(item),
                        "control": {
                            field: item.get(field)
                            for field in ("control_method", "frequency", "reaction_plan")
                        },
                    },
                )
            )
    if gaps:
        return _finding(
            "QCI-R003", "特殊特性控制覆盖", CheckStatus.CONTRADICTED,
            "特殊特性缺少完整控制方法、频次或反应计划：" + ", ".join(gaps), evidence, "HIGH",
            "在控制计划中补齐控制方法、频次和反应计划。", ("每个PFMEA特殊特性均有完整控制条目",),
        )
    return _finding("QCI-R003", "特殊特性控制覆盖", CheckStatus.PASS, "PFMEA特殊特性均由同一工序—特性pair的完整控制承接。", evidence, "LOW")


def _valid_revision_date_waiver(
    doc: dict[str, Any], event: dict[str, Any], approval_date: date
) -> bool:
    waiver = doc.get("approved_waiver")
    if not isinstance(waiver, dict):
        return False
    required_roles = {"QUALITY_MANAGER", "PROCESS_OWNER"}
    try:
        valid_from = date.fromisoformat(waiver["valid_from"])
        valid_until = date.fromisoformat(waiver["valid_until"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        waiver.get("document_id") == doc.get("document_id")
        and waiver.get("event_revision") == event.get("revision")
        and waiver.get("scope") == "REVISION_DATE_EXCEPTION"
        and required_roles.issubset(set(waiver.get("approved_roles", [])))
        and isinstance(waiver.get("waiver_id"), str)
        and bool(waiver["waiver_id"].strip())
        and isinstance(waiver.get("locator"), str)
        and bool(waiver["locator"].strip())
        and valid_from <= approval_date <= valid_until
    )


def rule_revision_after_approval(case: dict[str, Any], plan: ImpactPlan) -> Finding:
    approved_at = case["event"].get("approved_at")
    if not approved_at:
        return _finding(
            "QCI-R004", "文件修订日期门", CheckStatus.UNVERIFIABLE,
            "工程变更或质量事件缺少批准日期。", [_event_evidence(case["event"], "approved_at", "FIELD_ABSENT")], "HIGH",
        )
    stale: list[str] = []
    evidence: list[EvidenceRef] = []
    approval_date = date.fromisoformat(approved_at)
    for doc in (item for item in case["documents"] if item.get("status") == "APPROVED"):
        revision_date = doc.get("revision_date")
        if not revision_date:
            return _finding(
                "QCI-R004", "文件修订日期门", CheckStatus.UNVERIFIABLE,
                f"{doc['document_id']}缺少修订日期。", [_evidence(doc, "revision_date", "FIELD_ABSENT")], "HIGH",
            )
        evidence.append(_evidence(doc, "revision_date", revision_date))
        if date.fromisoformat(revision_date) < approval_date:
            if _valid_revision_date_waiver(doc, case["event"], approval_date):
                waiver = doc["approved_waiver"]
                evidence.append(
                    _evidence(
                        doc,
                        waiver["locator"],
                        {
                            "waiver_id": waiver["waiver_id"],
                            "scope": waiver["scope"],
                            "event_revision": waiver["event_revision"],
                            "approved_roles": waiver["approved_roles"],
                            "valid_from": waiver["valid_from"],
                            "valid_until": waiver["valid_until"],
                        },
                    )
                )
            else:
                stale.append(doc["document_id"])
    if stale:
        return _finding(
            "QCI-R004", "文件修订日期门", CheckStatus.CONTRADICTED,
            "文件修订日期早于事件批准且无有效结构化豁免：" + ", ".join(stale), evidence, "HIGH",
            "更新文件修订日期，或补充绑定文件、事件版本、角色、有效期和位置的结构化豁免。",
            ("所有受控文件修订日期不早于批准日期，或存在有效结构化豁免",),
        )
    return _finding(
        "QCI-R004", "文件修订日期门", CheckStatus.PASS,
        "所有受控文件修订日期均不早于事件批准日期，或具有有效结构化豁免。",
        evidence,
        "LOW",
    )


def rule_inspection_current_references(
    case: dict[str, Any],
    plan: ImpactPlan,
    reference_context: _ControlledReferenceContext | None = None,
) -> Finding:
    inspection = document_by_type(case, "INSPECTION_RECORD")
    sop = document_by_type(case, "SOP")
    control = document_by_type(case, "CONTROL_PLAN")
    if not inspection or not sop or not control:
        return _finding(
            "QCI-R005", "检验记录引用当前版本", CheckStatus.UNVERIFIABLE, "缺少检验记录、SOP或控制计划。",
            [_case_evidence(case, "documents[*].document_type", [doc.get("document_type") for doc in case["documents"]])],
        )
    references = inspection.get("fields", {}).get("references")
    if not isinstance(references, dict):
        return _finding(
            "QCI-R005", "检验记录引用当前版本", CheckStatus.UNVERIFIABLE,
            "检验记录缺少版本引用。", [_evidence(inspection, "fields.references", "FIELD_ABSENT")], "HIGH",
        )
    if set(references) == {"LEGACY_UNATTESTED"}:
        return _finding(
            "QCI-R005",
            "检验记录引用当前版本",
            CheckStatus.UNVERIFIABLE,
            "LEGACY_UNATTESTED：旧引用仅声明revision，不能证明document/source identity。",
            [_evidence(inspection, "fields.references.LEGACY_UNATTESTED", references["LEGACY_UNATTESTED"])],
            "HIGH",
            "从同一受控原始工件包重建Inspection、SOP和Control Plan引用身份。",
            ("引用由sealed raw-byte ReferenceContext证明",),
        )
    missing_roles = sorted({"SOP", "CONTROL_PLAN"} - set(references))
    if missing_roles:
        return _finding(
            "QCI-R005",
            "检验记录引用当前版本",
            CheckStatus.UNVERIFIABLE,
            "检验记录缺少必要受控引用：" + ", ".join(missing_roles),
            [_evidence(inspection, "fields.references", references)],
            "HIGH",
        )
    if not _is_sealed_reference_context(reference_context):
        return _finding(
            "QCI-R005",
            "检验记录引用当前版本",
            CheckStatus.UNVERIFIABLE,
            "SEALED_REFERENCE_CONTEXT_MISSING：JSON字段或marker不能证明引用来自同次原始字节。",
            [_evidence(inspection, "fields.references", references)],
            "HIGH",
            "通过受限raw bundle入口重建引用上下文。",
            ("ReferenceContext由同一不可变bytes快照内部构造",),
        )
    sealed_references = reference_context.references()
    sealed_evidence = reference_context.evidence()
    actual_targets = {"SOP": sop, "CONTROL_PLAN": control}
    evidence: list[EvidenceRef] = []
    mismatches: list[str] = []
    first_sealed_evidence = next(iter(sealed_evidence.values()), {})
    sealed_inspection = first_sealed_evidence.get("inspection", {})
    if (
        reference_context.inspection_document_id != inspection.get("document_id")
        or sealed_inspection.get("revision") != inspection.get("revision")
        or sealed_inspection.get("source_hash") != inspection.get("source_hash")
    ):
        mismatches.append("INSPECTION_RECORD")
    extra_roles = sorted(set(references) - {"SOP", "CONTROL_PLAN"})
    if extra_roles:
        mismatches.append("extra roles=" + ",".join(extra_roles))
    for role in ("SOP", "CONTROL_PLAN"):
        identity = references[role]
        expected = sealed_references.get(role)
        target = actual_targets[role]
        role_evidence = sealed_evidence.get(role, {})
        inspection_evidence = role_evidence.get("inspection", {})
        evidence.extend(
            [
                _evidence(
                    inspection,
                    inspection_evidence.get(
                        "document_id_locator", f"fields.references.{role}.document_id"
                    ),
                    identity.get("document_id"),
                ),
                _evidence(
                    inspection,
                    inspection_evidence.get(
                        "revision_locator", f"fields.references.{role}.revision"
                    ),
                    identity.get("revision"),
                ),
                _evidence(
                    inspection,
                    f"fields.references.{role}.source_hash",
                    identity.get("source_hash"),
                ),
                _evidence(target, "document_id", target.get("document_id")),
                _evidence(target, "revision", target.get("revision")),
                _evidence(target, "source_hash", target.get("source_hash")),
            ]
        )
        actual_target_identity = {
            "document_type": target.get("document_type"),
            "document_id": target.get("document_id"),
            "revision": target.get("revision"),
            "source_hash": target.get("source_hash"),
        }
        revision_artifact = target.get("revision_artifact")
        artifact_consistent = revision_artifact is None or (
            isinstance(revision_artifact, dict)
            and revision_artifact.get("artifact_id") == f"sha256:{target.get('source_hash')}"
        )
        if identity != expected or identity != actual_target_identity or not artifact_consistent:
            mismatches.append(role)
    if mismatches:
        return _finding(
            "QCI-R005", "检验记录引用当前版本", CheckStatus.CONTRADICTED,
            f"检验记录受控引用身份不一致：{', '.join(mismatches)}。", evidence, "HIGH",
            "更新检验记录的受控文件引用，并重新确认受影响检验结果。", ("检验记录仅引用当前批准版本",),
        )
    return _finding(
        "QCI-R005",
        "检验记录引用当前版本",
        CheckStatus.PASS,
        "检验记录引用已由同次原始字节证明的当前SOP与控制计划身份。",
        evidence,
        "LOW",
    )


def rule_validation_evidence(
    case: dict[str, Any],
    plan: ImpactPlan,
    validation_context: _ValidationEvidenceContext | None = None,
) -> Finding:
    event = case["event"]
    if not _is_sealed_validation_context(validation_context):
        migration = case.get("validation_migration")
        code = (
            "LEGACY_UNATTESTED/VALIDATION_CONTEXT_REQUIRED"
            if isinstance(migration, dict)
            and migration.get("status") == "LEGACY_UNATTESTED"
            else "VALIDATION_CONTEXT_REQUIRED"
        )
        return _finding(
            "QCI-R006", "事件有效性证据", CheckStatus.UNVERIFIABLE,
            f"{code}: 未提供由原始验证报告字节构造的封闭证据上下文。",
            [_event_evidence(event, "validation_evidence", code)], "HIGH",
            remediation="提供SOURCE/RESOLVED阶段的原始验证报告包并重新绑定事件主体。",
            acceptance=("全部计划证据由原始字节重建并与当前主体一致",),
        )
    validation_plan = event.get("validation_plan")
    if not isinstance(validation_plan, dict):
        return _finding(
            "QCI-R006", "事件有效性证据", CheckStatus.UNVERIFIABLE,
            "VALIDATION_PLAN_REQUIRED: 当前事件没有原生v0.4验证计划。",
            [_event_evidence(event, "validation_plan", "FIELD_ABSENT")], "HIGH",
        )
    requirements = {
        item["evidence_id"]: item
        for item in validation_plan.get("required_evidence", [])
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    }
    reports = {item["evidence_id"]: item for item in validation_context.reports()}
    missing = sorted(set(requirements) - set(reports))
    if missing:
        return _finding(
            "QCI-R006", "事件有效性证据", CheckStatus.UNVERIFIABLE,
            "REQUIRED_VALIDATION_EVIDENCE_MISSING: " + ", ".join(missing),
            [_event_evidence(event, "validation_plan.required_evidence", missing)], "HIGH",
        )
    extra = sorted(set(reports) - set(requirements))
    evidence: list[EvidenceRef] = []
    mismatches: list[str] = []
    if extra:
        mismatches.append("EXTRA_VALIDATION_EVIDENCE:" + ",".join(extra))
    for evidence_id in sorted(set(requirements) & set(reports)):
        requirement = requirements[evidence_id]
        report = reports[evidence_id]
        evidence.append(
            EvidenceRef(
                document_id=report["source_id"],
                revision=str(event.get("revision", "UNKNOWN")),
                locator=report["locator"],
                excerpt=_stable_excerpt(
                    {
                        "evidence_id": evidence_id,
                        "result": report["result"],
                        "event_id": report["event_id"],
                        "event_revision": report["event_revision"],
                        "scope_digest": report["scope_digest"],
                        "case_subject_hash": report["case_subject_hash"],
                        "issuer_id": report["issuer_id"],
                        "issued_at": report["issued_at"],
                    }
                ),
                source_hash=report["source_hash"],
            )
        )
        comparisons = {
            "RESULT_NOT_PASS": report["result"] == "PASS",
            "EVENT_ID_MISMATCH": report["event_id"] == event["event_id"],
            "EVENT_REVISION_MISMATCH": report["event_revision"] == event["revision"],
            "SCOPE_DIGEST_MISMATCH": report["scope_digest"] == validation_context.scope_digest,
            "CASE_SUBJECT_MISMATCH": report["case_subject_hash"] == validation_context.case_subject_hash,
            "EVIDENCE_TYPE_MISMATCH": report["evidence_type"] == requirement["evidence_type"],
            "CLAIM_MISMATCH": report["claim"] == requirement["claim"],
            "ISSUER_ID_MISMATCH": report["issuer_id"] == requirement["issuer_id"],
            "ISSUER_ROLE_MISMATCH": report["issuer_role"] == requirement["issuer_role"],
            "RULESET_VERSION_MISMATCH": report["ruleset_version"] == RULESET_VERSION,
            "CASE_SCHEMA_VERSION_MISMATCH": report["case_schema_version"] == case["schema_version"],
        }
        mismatches.extend(code for code, matched in comparisons.items() if not matched)
        performed = datetime.fromisoformat(report["performed_at"][:-1] + "+00:00")
        issued = datetime.fromisoformat(report["issued_at"][:-1] + "+00:00")
        valid_from = datetime.fromisoformat(requirement["valid_from"][:-1] + "+00:00")
        valid_until = datetime.fromisoformat(requirement["valid_until"][:-1] + "+00:00")
        if not (valid_from <= performed <= issued <= valid_until):
            mismatches.append("VALIDATION_TIME_WINDOW_MISMATCH")
    if mismatches:
        return _finding(
            "QCI-R006", "事件有效性证据", CheckStatus.CONTRADICTED,
            "VALIDATION_CLAIM_MISMATCH: " + ", ".join(sorted(set(mismatches))),
            evidence, "HIGH",
            "重新执行验证并从当前事件、范围与case主体生成原始报告。",
            ("required evidence exact set与当前subject逐字段一致",),
        )
    return _finding(
        "QCI-R006", "事件有效性证据", CheckStatus.PASS,
        "原始验证报告claim与当前event/scope/case/issuer/time计划逐项一致。",
        evidence, "LOW",
    )


def rule_high_risk_approval(case: dict[str, Any], plan: ImpactPlan) -> Finding:
    event = case["event"]
    risk_level = event.get("risk_level")
    if risk_level not in {"LOW", "MEDIUM", "HIGH"}:
        return _finding(
            "QCI-R007", "高风险事件审批记录完整性", CheckStatus.UNVERIFIABLE,
            "事件缺少可验证的风险等级，不得按非高风险放行。",
            [_event_evidence(event, "risk_level", risk_level)], "CRITICAL",
            remediation="补充经责任人确认的LOW/MEDIUM/HIGH风险等级。",
            acceptance=("风险等级存在且属于允许枚举",),
        )
    if risk_level != "HIGH":
        return _finding(
            "QCI-R007", "高风险事件审批记录完整性", CheckStatus.PASS,
            "事件不是高风险，无需检查高风险事件的合成角色与版本记录。",
            [_event_evidence(event, "risk_level", risk_level)], "LOW",
        )
    approvals = event.get("approvals")
    if not approvals:
        return _finding(
            "QCI-R007", "高风险事件审批记录完整性", CheckStatus.CONTRADICTED,
            "高风险事件没有合成审批角色与事件版本记录。",
            [_event_evidence(event, "approvals", "EMPTY_OR_ABSENT")], "CRITICAL",
            remediation="由质量负责人和工艺负责人完成批准或驳回。", acceptance=("质量负责人和工艺负责人均批准当前事件版本",),
        )
    current_approvals = [
        item for item in approvals if item.get("event_revision") == event.get("revision")
    ]
    non_approved = [
        item
        for item in current_approvals
        if item.get("decision") in {"REJECTED", "CHANGES_REQUESTED"}
    ]
    approval_evidence = [
        {
            "role": item.get("role"),
            "decision": item.get("decision"),
            "event_revision": item.get("event_revision"),
        }
        for item in current_approvals
    ]
    evidence = [_event_evidence(event, "approvals", approval_evidence)]
    if non_approved:
        return _finding(
            "QCI-R007", "高风险事件审批记录完整性", CheckStatus.CONTRADICTED,
            "高风险事件当前版本存在驳回或要求修改的审批记录。", evidence, "CRITICAL",
            "解决驳回/修改意见后，由必要角色重新审批当前事件版本。",
            ("当前事件版本不存在REJECTED或CHANGES_REQUESTED记录",),
        )
    roles = {
        item.get("role")
        for item in current_approvals
        if item.get("decision") == "APPROVED"
    }
    required = {"QUALITY_MANAGER", "PROCESS_OWNER"}
    if not required.issubset(roles):
        return _finding(
            "QCI-R007", "高风险事件审批记录完整性", CheckStatus.CONTRADICTED,
            "高风险事件缺少当前版本的必要合成角色记录：" + ", ".join(sorted(required - roles)), evidence, "CRITICAL",
            "补齐当前事件版本的角色记录；真实放行还需身份、签名和内容绑定系统。",
            ("质量负责人和工艺负责人角色记录均指向当前事件版本",),
        )
    return _finding(
        "QCI-R007", "高风险事件审批记录完整性", CheckStatus.PASS,
        "当前合成数据中必要角色与事件版本记录齐全；本规则不验证真实身份、签名或文档快照。",
        evidence,
        "LOW",
    )


RuleFunction = Callable[[dict[str, Any], ImpactPlan], Finding]

RULES: tuple[RuleFunction, ...] = (
    rule_process_coverage,
    rule_spec_consistency,
    rule_special_characteristic_control,
    rule_revision_after_approval,
    rule_inspection_current_references,
    rule_validation_evidence,
    rule_high_risk_approval,
)
