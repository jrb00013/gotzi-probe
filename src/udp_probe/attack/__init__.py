"""
Attack simulation (Tier 3): flood, port knock, slowloris, replay.
All operations are AUDIT-LOGGED to attack_sessions.
Use only on targets you are authorized to test.
"""

from .flood import run_udp_flood, run_tcp_flood
from .port_knock import run_port_knock
from .slowloris import run_slowloris
from .replay import run_replay_file, run_replay_pcap
from .audit import log_attack_session

__all__ = [
    "run_udp_flood",
    "run_tcp_flood",
    "run_port_knock",
    "run_slowloris",
    "run_replay_file",
    "run_replay_pcap",
    "log_attack_session",
]
