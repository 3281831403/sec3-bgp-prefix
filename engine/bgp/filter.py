"""Prefix filter used by the edge routing policy pipeline."""

from __future__ import annotations

import ipaddress

ALLOW = "allow"
DENY = "deny"


def _to_network(prefix):
    """Return an ipaddress network for a text or network input."""
    if isinstance(prefix, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return prefix
    return ipaddress.ip_network(str(prefix), strict=False)


def _parse_interval(length_text):
    """Parse an inclusive ``min-max`` interval into integers."""
    text = str(length_text).strip()
    pieces = text.split("-")

    if len(pieces) == 1:
        min_text = max_text = pieces[0]
    elif len(pieces) == 2 and pieces[0] and pieces[1]:
        min_text, max_text = pieces
    else:
        raise ValueError(f"invalid length interval: {length_text!r}")

    min_len = int(min_text)
    max_len = int(max_text)
    if min_len > max_len:
        raise ValueError(f"inverted length interval: {min_len}-{max_len}")
    return min_len, max_len


def _normalize_action(action):
    """Normalize an action token to lower case."""
    return str(action).strip().lower()


def parse_rules(rules):
    """Parse rule descriptions into dictionaries.

    A rule description contains the action, covered network, and inclusive
    prefix-length interval. Length bounds are returned as integers.
    """
    parsed = []
    for entry in rules:
        if isinstance(entry, dict):
            min_len, max_len = _parse_interval(
                f"{entry['min_len']}-{entry['max_len']}"
            )
            parsed.append(
                {
                    "action": _normalize_action(entry["action"]),
                    "prefix": _to_network(entry["prefix"]),
                    "min_len": min_len,
                    "max_len": max_len,
                    "text": entry.get("text", ""),
                }
            )
            continue

        action, prefix_text, length_text = str(entry).split()
        min_len, max_len = _parse_interval(length_text)
        parsed.append(
            {
                "action": _normalize_action(action),
                "prefix": _to_network(prefix_text),
                "min_len": min_len,
                "max_len": max_len,
                "text": str(entry),
            }
        )
    return parsed


def match_prefix(rule, prefix):
    """Return whether a prefix is covered by a parsed rule.

    Network coverage uses containment rather than textual equality, and the
    candidate prefix length must be within the inclusive interval.
    """
    rule_net = _to_network(rule["prefix"])
    candidate = _to_network(prefix)

    if candidate.version != rule_net.version:
        return False
    if not candidate.subnet_of(rule_net):
        return False

    min_len = int(rule["min_len"])
    max_len = int(rule["max_len"])
    return min_len <= candidate.prefixlen <= max_len


def check_as_path(path, policy):
    """Return whether every AS in the chain is permitted by the policy."""
    if not path:
        return False

    if not isinstance(policy, dict):
        policy = {}

    try:
        allowed = {int(asn) for asn in policy.get("allowed_asns", [])}
    except (TypeError, ValueError):
        return False

    if isinstance(path, str):
        tokens = path.replace(",", " ").split()
    else:
        try:
            tokens = list(path)
        except TypeError:
            return False

    try:
        chain = [int(asn) for asn in tokens]
    except (TypeError, ValueError):
        return False

    if not chain:
        return False
    return all(asn in allowed for asn in chain)


def apply_rules(rules, prefix):
    """Return the action selected for a prefix by a parsed rule list.

    Matching deny rules have absolute priority. Otherwise, at least one
    matching allow rule is required; the default and empty-rule-set verdict
    is deny.
    """
    if not rules:
        return DENY

    try:
        candidate = _to_network(prefix)
    except (ValueError, TypeError):
        return DENY

    for rule in rules:
        if _normalize_action(rule.get("action", "")) != DENY:
            continue
        try:
            if match_prefix(rule, candidate):
                return DENY
        except (KeyError, TypeError, ValueError):
            continue

    for rule in rules:
        if _normalize_action(rule.get("action", "")) != ALLOW:
            continue
        try:
            if match_prefix(rule, candidate):
                return ALLOW
        except (KeyError, TypeError, ValueError):
            continue

    return DENY


def check_min_length(prefix, rule):
    """Return whether the prefix length is inside the rule interval."""
    candidate = _to_network(prefix)
    min_len = int(rule["min_len"])
    max_len = int(rule["max_len"])
    return min_len <= candidate.prefixlen <= max_len


def evaluate(announcement, rules):
    """Evaluate one announcement and report the selected action."""
    if not isinstance(announcement, dict):
        return {"prefix": "", "action": DENY, "reason": "missing prefix"}

    prefix = announcement.get("prefix")
    if prefix is None:
        return {"prefix": "", "action": DENY, "reason": "missing prefix"}

    action = apply_rules(rules, prefix)
    reason = "" if action == ALLOW else "no allowing rule"

    if action == ALLOW:
        path = announcement.get("as_path")
        if path is not None:
            policy = announcement.get("as_policy") or {}
            if not check_as_path(path, policy):
                action = DENY
                reason = "as path not permitted"

    return {"prefix": str(prefix), "action": action, "reason": reason}


def validate_rules(rules):
    """Return the list of problems found in a rule collection."""
    if not rules:
        return ["empty rule set"]

    problems = []
    has_deny_rule = False

    for entry in rules:
        if isinstance(entry, dict):
            action = entry.get("action")
            prefix_value = entry.get("prefix")
            min_value = entry.get("min_len")
            max_value = entry.get("max_len")
            if (
                action is None
                or prefix_value is None
                or min_value is None
                or max_value is None
            ):
                problems.append(f"malformed rule: {entry}")
                continue
            interval_text = f"{min_value}-{max_value}"
        else:
            fields = str(entry).split()
            if len(fields) != 3:
                problems.append(f"malformed rule: {entry}")
                continue
            action, prefix_value, interval_text = fields

        action_name = _normalize_action(action)
        if action_name not in (ALLOW, DENY):
            problems.append(f"malformed rule: {entry}")
            continue

        has_deny_rule = has_deny_rule or action_name == DENY

        try:
            network = _to_network(prefix_value)
        except (ValueError, TypeError):
            problems.append(f"malformed rule: {entry}")
            continue

        try:
            min_len, max_len = _parse_interval(interval_text)
        except ValueError as exc:
            if "inverted" in str(exc):
                problems.append(f"inverted length interval: {entry}")
            else:
                problems.append(f"malformed length interval: {entry}")
            continue

        max_address_bits = 32 if network.version == 4 else 128
        if min_len < 0 or max_len > max_address_bits:
            problems.append(f"invalid length interval: {entry}")

    if not has_deny_rule:
        problems.append("policy must contain at least one deny rule")

    return problems


def prefix_batch(announcements, rules):
    """Filter announcements and map their prefixes to actions.

    Each announcement is judged independently; a verdict is never reused by
    a later announcement.
    """
    results = {}

    for announcement in announcements:
        if isinstance(announcement, dict):
            prefix = announcement.get("prefix")
        else:
            prefix = announcement

        if prefix is None:
            key = ""
            verdict = DENY
        else:
            key = str(prefix)
            verdict = apply_rules(rules, prefix)

        results[key] = verdict

    return results
