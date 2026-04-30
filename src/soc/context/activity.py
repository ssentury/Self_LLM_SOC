from __future__ import annotations

from collections import Counter

from soc.models import Flow, SourceActivitySummary
from soc.storage.sqlite import SQLiteEventStore


def summarize_source_activity(
    current_flow: Flow,
    previous_flows: list[Flow],
    window_minutes: int = 10,
) -> SourceActivitySummary:
    same_source = [flow for flow in previous_flows if flow.src_ip == current_flow.src_ip]
    ports = Counter(flow.dst_port for flow in same_source)
    return SourceActivitySummary(
        window_minutes=window_minutes,
        flow_count=len(same_source),
        distinct_dst_count=len({flow.dst_ip for flow in same_source}),
        top_dst_ports=[port for port, _ in ports.most_common(5)],
        recent_verdicts=[],
        summary_ko=(
            f"최근 {window_minutes}분 기준 같은 출발지 flow "
            f"{len(same_source)}건을 관찰했습니다."
        ),
    )


def summarize_source_activity_from_store(
    store: SQLiteEventStore,
    current_flow: Flow,
    window_minutes: int = 10,
) -> SourceActivitySummary:
    return store.summarize_source_activity(
        current_flow.src_ip,
        before_time=current_flow.start_ms,
        window_minutes=window_minutes,
    )
