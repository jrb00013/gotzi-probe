"""Honeypot: fake open ports / services; log connection attempts."""

from .server import run_honeypot, stop_honeypot

__all__ = ["run_honeypot", "stop_honeypot"]
