from fastapi import APIRouter

from udp_probe.core.config import get_config

router = APIRouter()


@router.get("")
def config_get():
    cfg = get_config()
    return {
        "host": cfg.host,
        "port": cfg.port,
        "probe_host": cfg.probe_host,
        "probe_port": cfg.probe_port,
        "probe_echo": cfg.probe_echo,
        "capture_interface": cfg.capture_interface,
        "pcap_dir": cfg.pcap_dir,
    }


@router.put("")
def config_put(
    probe_host: str | None = None,
    probe_port: int | None = None,
    probe_echo: bool | None = None,
    capture_interface: str | None = None,
):
    # Note: pydantic-settings typically reads from env; we don't persist PUT to disk here.
    # For full persistence you'd write to config.json or env file.
    cfg = get_config()
    out = {"message": "Config is read from environment (PROBE_*). Override with env vars."}
    if probe_host is not None:
        cfg.probe_host = probe_host
        out["probe_host"] = probe_host
    if probe_port is not None:
        cfg.probe_port = probe_port
        out["probe_port"] = probe_port
    if probe_echo is not None:
        cfg.probe_echo = probe_echo
        out["probe_echo"] = probe_echo
    if capture_interface is not None:
        cfg.capture_interface = capture_interface
        out["capture_interface"] = capture_interface
    return out
