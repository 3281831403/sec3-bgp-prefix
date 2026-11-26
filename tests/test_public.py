import ipaddress

from engine.bgp.filter import (
    apply_rules,
    check_as_path,
    match_prefix,
    parse_rules,
    prefix_batch,
)


def test_parse_rules_reads_action_prefix_and_interval():
    rules = parse_rules(["allow 10.0.0.0/8 8-24"])

    assert len(rules) == 1
    rule = rules[0]
    assert rule["action"] == "allow"
    assert rule["prefix"] == ipaddress.ip_network("10.0.0.0/8")
    assert rule["min_len"] == 8
    assert rule["max_len"] == 24


def test_prefix_match_uses_network_containment():
    rule = parse_rules(["allow 10.0.0.0/8 8-24"])[0]

    assert match_prefix(rule, "10.1.0.0/16") is True


def test_deny_rule_wins_over_allow_rule():
    rules = parse_rules(["allow 10.0.0.0/8 8-9", "deny 10.0.0.0/8 8-9"])

    assert apply_rules(rules, "10.0.0.0/8") == "deny"


def test_as_path_must_be_covered_by_policy():
    policy = {"allowed_asns": [65001]}

    assert check_as_path([65001], policy) is True
    assert check_as_path([65099, 65001], policy) is False


def test_batch_announcements_are_independent():
    rules = parse_rules(["allow 10.0.0.0/8 8-8", "deny 192.168.0.0/16 16-16"])

    result = prefix_batch(["10.0.0.0/8", "192.168.0.0/16"], rules)

    assert result == {"10.0.0.0/8": "allow", "192.168.0.0/16": "deny"}