"""IDS-style rules: match packet patterns (payload regex, port) and tag/alert."""

from .engine import RuleEngine, match_packet
from .service import list_rules, add_rule, delete_rule, enable_rule, run_rules_on_packet, list_rule_matches

__all__ = [
    "RuleEngine",
    "match_packet",
    "list_rules",
    "add_rule",
    "delete_rule",
    "enable_rule",
    "run_rules_on_packet",
    "list_rule_matches",
]
