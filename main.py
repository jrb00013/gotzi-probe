#!/usr/bin/env python3
"""
Gotzi — unified entry point (Wireshark-like toolkit).
Delegates to the udp_probe package CLI.
  TUI:   python main.py --tui   [--filter-port 12345]
  Web:   python main.py --web   [--port 8080] [--filter-port 12345]
  Server: python main.py --server
  Client: python main.py --client   [--count 10]
  Sniff:  python main.py --sniff   [--filter-port 12345]
  Discover: python main.py discover [CIDR|IP|range...] [--no-ping] [--no-http]
"""
import sys
from udp_probe.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
