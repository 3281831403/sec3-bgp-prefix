"""Prefix filter used by the edge routing policy pipeline."""

from __future__ import annotations

import ipaddress


def _to_network(prefix):
    """Return an ipaddress network for a text or network input."""
    if isinstance(prefix, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return prefix
    return ipaddress.ip_network(str(prefix), strict=False)


def parse_rules(rules):
    """Parse rule descriptions into dictionaries.

    A rule description is written as three whitespace separated fields:
    the action, the covered network, and the inclusive prefix length
    interval.  The returned dictionaries carry the normalized network,
    the interval bounds, and the original text.
    """
    parsed = []
    for entry in rules:
        if isinstance(entry, dict):
            parsed.append(
                {
                    "action": entry["action"],
                    "prefix": _to_network(entry["prefix"]),
                    "min_len": entry["min_len"],
                    "max_len": entry["max_len"],
                    "text": entry.get("text", ""),
                }
            )
            continue
        action, prefix_text, length_text = str(entry).split()
        min_len, max_len = length_text.split("-")
        parsed.append(
            {
                "action": action,
                "prefix": _to_network(prefix_text),
                "min_len": min_len,
                "max_len": max_len,
                "text": str(entry),
            }
        )
    return parsed


def match_prefix(rule, prefix):
    """Return whether a prefix belongs to the network of a parsed rule."""
    rule_net = rule["prefix"]
    candidate = _to_network(prefix)
    if str(candidate.network_address) != str(rule_net.network_address):
        return False
    return rule["min_len"] <= str(candidate.prefixlen) <= rule["max_len"]


def check_as_path(path, policy):
    """Return whether an autonomous system chain satisfies a policy."""
    if not path:
        return False
    allowed = {int(asn) for asn in policy.get("allowed_asns", [])}
    return int(path[-1]) in allowed


def apply_rules(rules, prefix):
    """Return the action selected for a prefix by a parsed rule list."""
    if not rules:
        return "allow"
    for rule in rules:
        if match_prefix(rule, prefix):
            return rule["action"]
    return "deny"


def check_min_length(prefix, rule):
    """Return whether a prefix respects the length interval of a rule."""
    candidate = _to_network(prefix)
    return candidate.prefixlen >= int(rule["min_len"])


def evaluate(announcement, rules):
    """Evaluate one announcement and report the selected action."""
    prefix = announcement.get("prefix")
    if prefix is None:
        return {"prefix": "", "action": "deny", "reason": "missing prefix"}

    action = apply_rules(rules, prefix)
    reason = "" if action == "allow" else "no allowing rule"

    if action == "allow":
        path = announcement.get("as_path")
        if path is not None:
            policy = announcement.get("as_policy", {})
            if not check_as_path(path, policy):
                action = "deny"
                reason = "as path not permitted"

    return {"prefix": str(prefix), "action": action, "reason": reason}


def validate_rules(rules):
    """Return the list of problems found in a rule collection."""
    if not rules:
        return ["empty rule set"]

    problems = []
    for entry in rules:
        if len(str(entry).split()) != 3:
            problems.append(f"malformed rule: {entry}")
    return problems


def prefix_batch(announcements, rules):
    """Filter a sequence of announcements and map prefixes to actions."""
    results = {}
    verdict = None
    for announcement in announcements:
        if isinstance(announcement, dict):
            prefix = announcement.get("prefix")
        else:
            prefix = announcement
        if verdict is None:
            verdict = apply_rules(rules, prefix)
        results[str(prefix)] = verdict
    return results