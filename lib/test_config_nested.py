from pathlib import Path

from omegaconf import OmegaConf

from lib.config import SshTunnelConfig, _dict_to_config

DEFAULT = Path(__file__).parent.parent / "config" / "default.yaml"


def _screen_share_apps(apps: list[dict]) -> list:
    merged = OmegaConf.merge(OmegaConf.load(DEFAULT), {"screen_share": {"apps": apps}})
    return _dict_to_config(OmegaConf.to_container(merged)).screen_share.apps


def test_optional_nested_dataclass_is_built() -> None:
    [app] = _screen_share_apps(
        [{"connection": "c", "ssh_tunnel": {"host": "vnc.example.com", "port": 2222}}]
    )
    assert app.ssh_tunnel == SshTunnelConfig(host="vnc.example.com", port=2222)


def test_optional_nested_dataclass_absent_stays_none() -> None:
    [app] = _screen_share_apps([{"connection": "c"}])
    assert app.ssh_tunnel is None
    assert app.fallback_app is None
