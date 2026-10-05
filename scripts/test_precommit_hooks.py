"""Every hook stage declared in .pre-commit-config.yaml must be one `make hooks` installs.

`pre-commit install` writes one hook file per entry of
`default_install_hook_types`. A hook declared for any other stage is silently
never run.
"""

from pathlib import Path

from omegaconf import OmegaConf

CONFIG = Path(__file__).resolve().parent.parent / ".pre-commit-config.yaml"


def test_every_declared_stage_is_installed() -> None:
    config = OmegaConf.to_container(OmegaConf.load(CONFIG))
    assert isinstance(config, dict)
    installed = set(config["default_install_hook_types"])
    declared = {
        (hook["id"], stage)
        for repo in config["repos"]
        for hook in repo["hooks"]
        for stage in hook["stages"]
    }
    assert declared, "no hook declares a stage"
    missing = sorted((hook_id, stage) for hook_id, stage in declared if stage not in installed)
    assert not missing, f"declared but never installed: {missing}"
