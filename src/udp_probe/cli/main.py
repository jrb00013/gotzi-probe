"""
Gotzi — unified CLI entry point (Wireshark-like).
  TUI:       python -m udp_probe --tui   or   gotzi --tui
  Web:       python -m udp_probe --web   [--port 8080] [--filter-port 12345]
  Server:    python -m udp_probe --server
  Client:    python -m udp_probe --client   [--count 10]
  Sniff:     python -m udp_probe --sniff   [--port 12345]
  Discover:  python -m udp_probe discover [targets...] [--no-ping] [--no-http]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from udp_probe.capture import (
    PacketStore,
    run_probe_client,
    run_probe_server,
    run_live_sniffer,
)
from udp_probe.ui import UDPProbeTUI, run_web


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Gotzi — Wireshark-like TUI, Web UI, Server, Client, Sniffer, Discover"
    )
    parser.add_argument("--tui", action="store_true", help="Run the TUI packet sniffer")
    parser.add_argument("--web", action="store_true", help="Run the web UI (Wireshark-like)")
    parser.add_argument("--server", action="store_true", help="Run the UDP probe server")
    parser.add_argument("--client", action="store_true", help="Run the UDP probe client")
    parser.add_argument("--sniff", action="store_true", help="Run CLI sniffer (print packets to stdout)")
    parser.add_argument("--port", type=int, default=8080, help="Port for web UI (default 8080)")
    parser.add_argument("--filter-port", type=int, default=None, help="Filter capture by UDP port")
    parser.add_argument("--count", type=int, default=10, help="Probe count for client")
    parser.add_argument(
        "positional",
        nargs="*",
        help="For 'discover' mode: pass 'discover' then targets (CIDR, IP, or range).",
    )
    args, rest = parser.parse_known_args()

    # discover: python -m udp_probe discover [targets...] [--no-ping] [--no-http] ...
    if args.positional and args.positional[0] == "discover":
        # discover_cli.main() uses argparse on sys.argv; fake argv so targets and flags are parsed
        sys.argv = ["udp_probe discover"] + args.positional[1:] + rest
        from udp_probe.discovery.discover_cli import main as discover_main
        return discover_main()

    if args.tui:
        UDPProbeTUI(filter_port=args.filter_port).run()
        return 0

    if args.web:
        run_web(port=args.port, filter_port=args.filter_port)
        return 0

    if args.server:
        run_probe_server()
        return 0

    if args.client:
        try:
            with open(Path("config.json")) as f:
                cfg = json.load(f)
            target_ip, target_port = cfg["host"], cfg["port"]
        except Exception:
            target_ip, target_port = "127.0.0.1", 12345
        print(f"[+] Sending {args.count} UDP packets to {target_ip}:{target_port}")
        results = run_probe_client(target_ip, target_port, count=args.count)
        for r in results:
            rtt = r["rtt_ms"]
            if rtt >= 0:
                print(f"  [{r['probe_id']}] RTT: {rtt:.2f} ms")
            else:
                print(f"  [{r['probe_id']}] No response (timeout)")
        return 0

    if args.sniff:
        store = PacketStore(max_packets=10_000)

        def on_packet(p):
            print(f"  #{p.index} {p.src_ip}:{p.src_port} -> {p.dest_ip}:{p.dest_port} len={p.length} {p.summary[:60]!r}", flush=True)

        print(f"[*] Sniffing UDP (filter_port={args.filter_port}). Ctrl+C to stop.", flush=True)
        try:
            run_live_sniffer(store, filter_port=args.filter_port, on_packet=on_packet)
        except KeyboardInterrupt:
            pass
        return 0

    parser.print_help()
    return 0


def main() -> int:
    return _main()


if __name__ == "__main__":
    sys.exit(main())
