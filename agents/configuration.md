# Configuration

Part of the agent guide: [AGENTS.md](../AGENTS.md).

**OmegaConf Config System**: This project uses OmegaConf with hierarchical YAML configuration:
- `config/default.yaml` - Safe defaults (checked into git)
- `config/local.yaml` - Secrets and overrides (gitignored)
- `lib/config.py` - Dataclass-based structured configs with type safety

**Configuration Access Pattern**:
```python
from lib.config import get_config

cfg = get_config()
email = cfg.tesla.powerwall_email
tokens = cfg.pushover.tokens["Powerwall"]
```

**Hot Reload Support** (for long-running processes):
```python
from lib.config import reset_config, get_config

reset_config()  # Clear cached config
cfg = get_config()  # Reload from YAML
```

**Initial Setup**: Create `config/local.yaml` with your overrides (only add values you want to change):
```yaml
tesla:
  powerwall_email: your@email.com
  powerwall_password: your_password

pushover:
  user: your_pushover_user
  tokens:
    Powerwall: your_token
```

Config merges default.yaml + local.yaml hierarchically.

## Changing config
- Add a dataclass to `lib/config.py` for any new module's config, then register it in the root `Config` dataclass. Never `cfg_dict.get("your_key")` — the config system exists to give you type-checked access.
- `config/default.yaml` holds safe placeholders committed to git. `config/local.yaml` overrides with secrets and per-host values (gitignored, symlinked to `~/bin/Common-configs/Code_config_local.yaml`).
- If your module has multiple credentials, put them under a single top-level key (`ring:`, `august:`) so config diff reviews stay coherent.
