from __future__ import annotations

from typing import Any

from .loader import relationship_key
from .models import ImpactPlan


RULE_IDS = (
    "QCI-R001",
    "QCI-R002",
    "QCI-R003",
    "QCI-R004",
    "QCI-R005",
    "QCI-R006",
    "QCI-R007",
)

REQUIRED_TYPES = (
    "PROCESS_FLOW",
    "PFMEA",
    "CONTROL_PLAN",
    "SOP",
    "INSPECTION_RECORD",
)


def build_impact_plan(case: dict[str, Any]) -> ImpactPlan:
    event = case["event"]
    steps = tuple(sorted(set(event.get("affected_process_steps", []))))
    characteristics = tuple(sorted(set(event.get("affected_characteristics", []))))
    links = tuple(
        sorted(
            (
                (item["process_step_id"], item["characteristic_id"])
                for item in event.get("affected_links", [])
                if isinstance(item, dict)
                and isinstance(item.get("process_step_id"), str)
                and isinstance(item.get("characteristic_id"), str)
            ),
            key=lambda pair: relationship_key(*pair),
        )
    )
    reasoning = (
        f"事件 {event['event_id']} 类型为 {event.get('event_type', 'UNKNOWN')}",
        f"受影响工序：{', '.join(steps) if steps else '未提供'}",
        f"受影响特性：{', '.join(characteristics) if characteristics else '未提供'}",
        "受影响关系："
        + (
            ", ".join(f"({step}, {characteristic})" for step, characteristic in links)
            if links
            else "未提供"
        ),
        "工程变更触发流程、风险、控制、作业与检验五类文档回归",
    )
    return ImpactPlan(
        event_id=event["event_id"],
        affected_process_steps=steps,
        affected_characteristics=characteristics,
        affected_links=links,
        required_document_types=REQUIRED_TYPES,
        selected_rule_ids=RULE_IDS,
        reasoning_path=reasoning,
    )
