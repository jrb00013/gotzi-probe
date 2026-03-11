"""Run Gotzi CLI: python -m udp_probe [--tui | --web | --server | --client | --sniff] [discover [targets...]]"""
from udp_probe.cli.main import main
import sys
sys.exit(main())
