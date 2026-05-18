from __future__ import annotations

import json
import ipaddress
import re
from pathlib import Path
from typing import Any, NamedTuple

from soc.models import Flow, SourceActivitySummary, WatchlistMatch


REVIEWABLE_MATCH_STRENGTHS = {
    "review_candidate",
    "behavioral_review",
    "behavior",
    "threat_source",
    "policy_violation",
    "critical_forbidden",
}
STRONG_MATCH_STRENGTHS = REVIEWABLE_MATCH_STRENGTHS
MIN_DYNAMIC_REVIEW_THRESHOLD = 0.04
MAX_DYNAMIC_REVIEW_THRESHOLD = 0.30
_STRENGTH_RANK = {
    "none": 0,
    "asset_only": 1,
    "asset_service": 2,
    "review_candidate": 3,
    "behavioral_review": 4,
    "behavior": 5,
    "threat_source": 6,
    "policy_violation": 7,
    "critical_forbidden": 8,
}


EMPTY_WATCHLIST: dict[str, Any] = {
    "watchlist_version": "empty",
    "priority_1": [],
    "priority_2": [],
    "priority_3": [],
}


def load_watchlist(path: str | Path) -> dict[str, Any]:
    watchlist_path = Path(path)
    if not watchlist_path.exists():
        return dict(EMPTY_WATCHLIST)

    text = watchlist_path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            data = yaml.safe_load(text)
        except Exception:
            return dict(EMPTY_WATCHLIST)

    if not isinstance(data, dict):
        return dict(EMPTY_WATCHLIST)
    for priority in ("priority_1", "priority_2", "priority_3"):
        if not isinstance(data.get(priority), list):
            data[priority] = []
    return lint_watchlist(data)


def lint_watchlist(watchlist: dict[str, Any]) -> dict[str, Any]:
    warnings: list[str] = []
    for priority in ("priority_1", "priority_2", "priority_3"):
        for item in watchlist.get(priority, []):
            if not isinstance(item, dict):
                continue
            item_warnings: list[str] = []
            raw_hints = item.get("detection_hints", [])
            if not isinstance(raw_hints, list):
                raw_hints = []
                item_warnings.append("detection_hints is not a list; treated as empty.")
            hint_results = [_classify_hint(hint) for hint in raw_hints]
            unrecognized = [result.field for result in hint_results if result.kind == "unrecognized"]
            routable = _has_routable_hint_contract(hint_results)
            routing_policy = _lint_routing_policy(item.get("routing_policy"), item_warnings)
            if item.get("routing_policy") is not None and routing_policy is None:
                item.pop("routing_policy", None)
            if priority == "priority_1" and not routable:
                item["context_only"] = True
                item_warnings.append(
                    "priority_1 item has no reviewable machine-readable trigger; treated as context_only."
                )
            if routing_policy is not None:
                if priority != "priority_1":
                    item_warnings.append("routing_policy ignored because item is not priority_1.")
                    item.pop("routing_policy", None)
                elif bool(item.get("context_only")):
                    item_warnings.append("routing_policy ignored because item is context_only.")
                    item.pop("routing_policy", None)
                else:
                    item["routing_policy"] = routing_policy
            if unrecognized:
                item_warnings.append(
                    "unrecognized detection_hints fields: " + ", ".join(sorted(set(unrecognized)))
                )
            if _mentions_known_bad(item) and not _has_field(hint_results, {"src_ip", "known_bad_source"}):
                item_warnings.append(
                    "reason/escalation mentions known bad source but no src_ip/known_bad_source hint exists."
                )
            if _mentions_imds(item) and not _has_dst_ip_hint(item, "169.254.169.254"):
                item_warnings.append(
                    "reason/escalation mentions IMDS but no dst_ip == 169.254.169.254 hint exists."
                )
            if item_warnings:
                item["linter_warnings"] = item_warnings
                item_id = str(item.get("id") or "<missing-id>")
                warnings.extend(f"{priority}:{item_id}: {warning}" for warning in item_warnings)
    watchlist["linter_warnings"] = warnings
    return watchlist


def match_watchlist(
    flow: Flow,
    watchlist: dict[str, Any],
    *,
    ml_prob: float | None = None,
    source_activity: SourceActivitySummary | None = None,
) -> WatchlistMatch:
    best = WatchlistMatch(matched=False)
    for priority in ("priority_1", "priority_2", "priority_3"):
        for item in watchlist.get(priority, []):
            if not isinstance(item, dict):
                continue
            if not _target_asset_matches(flow, item):
                continue
            base_conditions = _target_asset_match_conditions(flow, item)
            hint_result = _match_detection_hints(
                flow,
                item.get("detection_hints", []),
                base_conditions=base_conditions,
                ml_prob=ml_prob,
                source_activity=source_activity,
            )
            candidate = WatchlistMatch(
                matched=True,
                priority=priority,
                item_id=item.get("id"),
                reason=item.get("reason"),
                matched_conditions=hint_result.conditions,
                alert_when=_string_list(item.get("alert_when")),
                likely_benign_when=_string_list(item.get("likely_benign_when")),
                match_strength=hint_result.strength,
                scope_matched=True,
                trigger_matched=hint_result.strength in REVIEWABLE_MATCH_STRENGTHS,
                context_only=bool(item.get("context_only")),
                linter_warnings=_string_list(item.get("linter_warnings")),
                escalation_hint=item.get("escalation_rule"),
                routing_policy=_dict_or_none(item.get("routing_policy")),
            )
            if _is_better_match(candidate, best):
                best = candidate
    return best


def _target_asset_matches(flow: Flow, item: dict[str, Any]) -> bool:
    return bool(_target_asset_match_conditions(flow, item))


def _target_asset_match_conditions(flow: Flow, item: dict[str, Any]) -> list[str]:
    assets = item.get("target_assets", [])
    if not isinstance(assets, list):
        return []
    conditions: list[str] = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        match_side = str(asset.get("match") or "either").strip().lower()
        if match_side not in {"src", "dst", "either"}:
            match_side = "either"
        ip = str(asset.get("ip") or "").strip()
        if ip and match_side in {"dst", "either"} and ip == flow.dst_ip:
            conditions.append("target_assets.ip == flow.dst_ip")
        if ip and match_side in {"src", "either"} and ip == flow.src_ip:
            conditions.append("target_assets.ip == flow.src_ip")
        cidr = str(asset.get("cidr") or "").strip()
        if cidr and match_side in {"dst", "either"} and _ip_in_any_cidr(flow.dst_ip, [cidr]):
            conditions.append(f"target_assets.cidr {cidr} contains flow.dst_ip")
        if cidr and match_side in {"src", "either"} and _ip_in_any_cidr(flow.src_ip, [cidr]):
            conditions.append(f"target_assets.cidr {cidr} contains flow.src_ip")
    return conditions


class HintClassification(NamedTuple):
    field: str
    kind: str
    strength: str
    operator: str = ""
    value: Any = None


class HintMatchResult(NamedTuple):
    conditions: list[str]
    strength: str


def _match_detection_hints(
    flow: Flow,
    hints: Any,
    *,
    base_conditions: list[str],
    ml_prob: float | None,
    source_activity: SourceActivitySummary | None,
) -> HintMatchResult:
    if not isinstance(hints, list) or not hints:
        return HintMatchResult(base_conditions, "asset_only")

    matched = list(base_conditions)
    matched_results: list[SingleHintResult] = []
    recognized = 0
    strongest = "asset_only"
    for hint in hints:
        result = _match_hint(flow, hint, ml_prob=ml_prob, source_activity=source_activity)
        if result.status == "unrecognized":
            continue
        recognized += 1
        if result.status == "no_match":
            continue
        matched.append(result.condition)
        matched_results.append(result)
        strongest = _stronger(strongest, result.strength)
    if recognized == 0:
        return HintMatchResult(matched, "asset_only")
    return HintMatchResult(
        matched,
        _combined_match_strength(
            base_conditions=base_conditions,
            matched_results=matched_results,
            strongest=strongest,
        ),
    )


class SingleHintResult(NamedTuple):
    status: str
    condition: str
    strength: str
    field: str = ""
    operator: str = ""
    value: Any = None


def _match_hint(
    flow: Flow,
    hint: Any,
    *,
    ml_prob: float | None,
    source_activity: SourceActivitySummary | None,
) -> SingleHintResult:
    if isinstance(hint, dict):
        field = str(hint.get("field", "")).strip()
        operator = str(hint.get("operator", "")).strip()
        value = hint.get("value")
        actual = _flow_value(flow, field, ml_prob, source_activity)
        if actual is _MISSING or not operator:
            return SingleHintResult("unrecognized", "", "none", field, operator, value)
        if _operator_matches(actual, operator, value):
            return SingleHintResult(
                "match",
                _condition_text(field, operator, value),
                _hint_strength(field, operator, value),
                field,
                operator,
                value,
            )
        return SingleHintResult("no_match", "", _hint_strength(field, operator, value), field, operator, value)

    if isinstance(hint, str):
        dst_port_match = re.search(r"(?:dst_port|L4_DST_PORT)\s+in\s+\[([^\]]+)\]", hint)
        if dst_port_match:
            values = {int(part.strip()) for part in dst_port_match.group(1).split(",")}
            if flow.dst_port in values:
                return SingleHintResult("match", hint, "asset_service", "dst_port", "in", sorted(values))
            return SingleHintResult("no_match", "", "asset_service", "dst_port", "in", sorted(values))
        return SingleHintResult("unrecognized", "", "none")

    return SingleHintResult("unrecognized", "", "none")


_MISSING = object()


def _flow_value(
    flow: Flow,
    field: str,
    ml_prob: float | None,
    source_activity: SourceActivitySummary | None,
) -> Any:
    aliases = {
        "L4_SRC_PORT": "src_port",
        "L4_DST_PORT": "dst_port",
        "PROTOCOL": "protocol",
    }
    field = aliases.get(field, field)
    if field == "src_ip":
        return flow.src_ip
    if field == "dst_ip":
        return flow.dst_ip
    if field == "src_port":
        return flow.src_port
    if field == "dst_port":
        return flow.dst_port
    if field == "protocol":
        return flow.protocol
    if field == "ml_prob":
        return ml_prob if ml_prob is not None else _MISSING
    if source_activity is not None:
        activity_values = {
            "recent_source_flow_count": source_activity.flow_count,
            "recent_source_distinct_dst_count": source_activity.distinct_dst_count,
            "recent_source_same_dst_count": source_activity.same_src_same_dst_count,
            "recent_source_same_dst_port_count": source_activity.same_src_same_dst_port_count,
            "same_src_same_dst_count": source_activity.same_src_same_dst_count,
            "same_src_same_dst_port_count": source_activity.same_src_same_dst_port_count,
            "watchlist_hit_count": source_activity.watchlist_hit_count,
            "recent_source_watchlist_hit_count": source_activity.watchlist_hit_count,
            "recent_alert_count": source_activity.recent_alert_count,
            "recent_source_alert_count": source_activity.recent_alert_count,
        }
        if field in activity_values:
            return activity_values[field]
    if field in flow.features:
        return flow.features[field]
    return _MISSING


def _operator_matches(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "in" and isinstance(expected, list):
        return any(_scalar_equal(actual, value) for value in expected)
    if operator in {"not_in", "nin"} and isinstance(expected, list):
        return not any(_scalar_equal(actual, value) for value in expected)
    if operator == "in_cidr" and isinstance(expected, list):
        return _ip_in_any_cidr(actual, expected)
    if operator == "not_in_cidr" and isinstance(expected, list):
        return not _ip_in_any_cidr(actual, expected)
    if operator == "eq":
        return _scalar_equal(actual, expected)
    if operator in {"gt", "gte", "lt", "lte"}:
        try:
            actual_number = float(actual)
            expected_number = float(expected)
        except (TypeError, ValueError):
            return False
        if operator == "gt":
            return actual_number > expected_number
        if operator == "gte":
            return actual_number >= expected_number
        if operator == "lt":
            return actual_number < expected_number
        return actual_number <= expected_number
    return False


def _ip_in_any_cidr(actual: Any, cidrs: list[Any]) -> bool:
    try:
        ip = ipaddress.ip_address(str(actual))
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def _scalar_equal(actual: Any, expected: Any) -> bool:
    if isinstance(actual, bool) or isinstance(expected, bool):
        return _to_bool(actual) == _to_bool(expected)
    try:
        return float(actual) == float(expected)
    except (TypeError, ValueError):
        return str(actual) == str(expected)


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _condition_text(field: str, operator: str, value: Any) -> str:
    if operator == "eq":
        return f"{field} == {value}"
    if operator in {"in", "in_cidr"}:
        return f"{field} in {value}"
    if operator in {"not_in", "nin", "not_in_cidr"}:
        return f"{field} not in {value}"
    return f"{field} {operator} {value}"


def _classify_hint(hint: Any) -> HintClassification:
    if isinstance(hint, dict):
        field = str(hint.get("field", "")).strip()
        operator = str(hint.get("operator", "")).strip()
        value = hint.get("value")
        if not field or not operator:
            return HintClassification(field or "<missing>", "unrecognized", "none", operator, value)
        return HintClassification(field, "recognized", _hint_strength(field, operator, value), operator, value)
    if isinstance(hint, str) and re.search(r"(?:dst_port|L4_DST_PORT)\s+in\s+\[([^\]]+)\]", hint):
        return HintClassification("dst_port", "recognized", "asset_service", "in", None)
    return HintClassification(str(hint)[:40] or "<missing>", "unrecognized", "none")


def _hint_strength(field: str, operator: str = "", value: Any = None) -> str:
    field = {"L4_DST_PORT": "dst_port", "PROTOCOL": "protocol"}.get(field, field)
    if field in {"dst_port", "protocol", "src_port"}:
        return "asset_service"
    if field == "dst_ip":
        if _hint_matches_ip(value, "169.254.169.254") and operator in {"eq", "in"}:
            return "review_candidate"
        if operator in {"not_in", "nin", "not_in_cidr"}:
            return "review_candidate"
        return "asset_service"
    if field == "src_ip":
        if operator in {"not_in", "nin", "not_in_cidr"}:
            return "policy_violation"
        if operator == "in":
            return "threat_source"
        if operator == "in_cidr":
            return "review_candidate"
        return "review_candidate"
    if field == "known_bad_source":
        return "threat_source"
    if field in {"policy_violation", "src_zone", "dst_zone", "business_window"}:
        return "policy_violation"
    if field in {"dst_external", "src_external", "external_destination", "approved_destination"}:
        return "behavioral_review"
    if field == "ml_prob" or field.startswith("recent_source_") or field in {
        "same_src_same_dst_count",
        "same_src_same_dst_port_count",
        "watchlist_hit_count",
        "recent_alert_count",
        "repeated_attempts",
        "failed_attempts",
        "bytes_out",
        "bytes_in",
    }:
        return "behavior"
    return "none"


def _combined_match_strength(
    *,
    base_conditions: list[str],
    matched_results: list[SingleHintResult],
    strongest: str,
) -> str:
    if not matched_results:
        return "asset_only"
    if _matches_metadata_access(matched_results):
        return "critical_forbidden"
    if strongest in {"behavior", "threat_source", "policy_violation", "critical_forbidden"}:
        return strongest

    reviewish = [result for result in matched_results if result.strength == "review_candidate"]
    asset_service = [result for result in matched_results if result.strength == "asset_service"]
    if reviewish and asset_service:
        if _matches_external_egress(matched_results, base_conditions):
            return "behavioral_review"
        return "review_candidate"
    if strongest == "behavioral_review":
        return "behavioral_review" if asset_service else "asset_only"
    if strongest == "review_candidate":
        return "asset_service" if asset_service else "asset_only"
    return strongest


def _matches_metadata_access(results: list[SingleHintResult]) -> bool:
    return _has_hint_result(results, "dst_ip", {"eq", "in"}, "169.254.169.254") and _has_port_result(
        results, 80
    )


def _matches_external_egress(
    results: list[SingleHintResult],
    base_conditions: list[str],
) -> bool:
    source_scoped = any("flow.src_ip" in condition for condition in base_conditions)
    external_destination = any(
        result.field == "dst_ip" and result.operator in {"not_in", "nin", "not_in_cidr"}
        for result in results
    )
    egress_port = any(
        result.field == "dst_port"
        and _value_contains_any(result.value, {53, 80, 443, 8080, 8443})
        for result in results
    )
    return source_scoped and external_destination and egress_port


def _has_routable_hint_contract(hints: list[HintClassification]) -> bool:
    strengths = [hint.strength for hint in hints if hint.kind == "recognized"]
    if any(strength in {"behavior", "threat_source", "policy_violation", "critical_forbidden"} for strength in strengths):
        return True
    has_review_candidate = any(strength in {"review_candidate", "behavioral_review"} for strength in strengths)
    has_asset_service = "asset_service" in strengths
    return has_review_candidate and has_asset_service


def _has_hint_result(
    results: list[SingleHintResult],
    field: str,
    operators: set[str],
    expected: Any,
) -> bool:
    return any(
        result.field == field
        and result.operator in operators
        and _value_contains_any(result.value, {expected})
        for result in results
    )


def _has_port_result(results: list[SingleHintResult], port: int) -> bool:
    return any(result.field == "dst_port" and _value_contains_any(result.value, {port}) for result in results)


def _value_contains_any(value: Any, expected_values: set[Any]) -> bool:
    values = value if isinstance(value, list) else [value]
    return any(any(_scalar_equal(candidate, expected) for expected in expected_values) for candidate in values)


def _hint_matches_ip(value: Any, ip: str) -> bool:
    return _value_contains_any(value, {ip})


def _lint_routing_policy(raw: Any, warnings: list[str]) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        warnings.append("routing_policy is not an object; ignored.")
        return None

    action = str(raw.get("action") or "tier1_llm").strip()
    if action != "tier1_llm":
        warnings.append("routing_policy.action must be tier1_llm; ignored.")
        return None

    try:
        review_threshold = float(raw.get("review_threshold"))
    except (TypeError, ValueError):
        warnings.append("routing_policy.review_threshold must be a number; ignored.")
        return None
    if review_threshold < MIN_DYNAMIC_REVIEW_THRESHOLD:
        warnings.append(
            f"routing_policy.review_threshold below {MIN_DYNAMIC_REVIEW_THRESHOLD:.2f}; ignored."
        )
        return None
    if review_threshold > MAX_DYNAMIC_REVIEW_THRESHOLD:
        warnings.append(
            f"routing_policy.review_threshold above {MAX_DYNAMIC_REVIEW_THRESHOLD:.2f}; ignored."
        )
        return None

    policy: dict[str, Any] = {
        "review_threshold": review_threshold,
        "action": "tier1_llm",
    }
    if "max_threshold_drop" in raw:
        try:
            policy["max_threshold_drop"] = float(raw["max_threshold_drop"])
        except (TypeError, ValueError):
            warnings.append("routing_policy.max_threshold_drop must be a number; ignored.")
    if raw.get("reason"):
        policy["reason"] = str(raw["reason"])
    return policy


def _is_better_match(candidate: WatchlistMatch, current: WatchlistMatch) -> bool:
    candidate_rank = _STRENGTH_RANK.get(candidate.match_strength, 0)
    current_rank = _STRENGTH_RANK.get(current.match_strength, 0)
    if candidate_rank != current_rank:
        return candidate_rank > current_rank
    if candidate.priority == current.priority:
        return False
    priority_rank = {"priority_1": 3, "priority_2": 2, "priority_3": 1, None: 0}
    return priority_rank.get(candidate.priority, 0) > priority_rank.get(current.priority, 0)


def _stronger(left: str, right: str) -> str:
    return left if _STRENGTH_RANK.get(left, 0) >= _STRENGTH_RANK.get(right, 0) else right


def _has_field(hints: list[HintClassification], fields: set[str]) -> bool:
    return any(hint.field in fields for hint in hints)


def _has_dst_ip_hint(item: dict[str, Any], dst_ip: str) -> bool:
    for hint in item.get("detection_hints", []):
        if not isinstance(hint, dict) or str(hint.get("field")) != "dst_ip":
            continue
        value = hint.get("value")
        if hint.get("operator") == "eq" and str(value) == dst_ip:
            return True
        if hint.get("operator") == "in" and isinstance(value, list) and dst_ip in {str(v) for v in value}:
            return True
    return False


def _mentions_known_bad(item: dict[str, Any]) -> bool:
    text = " ".join(str(item.get(key) or "") for key in ("reason", "escalation_rule")).lower()
    return any(token in text for token in ("known", "malicious", "threat ip", "악성", "위협 ip"))


def _mentions_imds(item: dict[str, Any]) -> bool:
    text = " ".join(str(item.get(key) or "") for key in ("reason", "escalation_rule")).lower()
    return "169.254.169.254" in text or "imds" in text or "metadata" in text


def _string_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if item is not None]


def _dict_or_none(raw: Any) -> dict[str, Any] | None:
    return dict(raw) if isinstance(raw, dict) else None
