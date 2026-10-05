# Testing

Part of the agent guide: [AGENTS.md](../AGENTS.md).

**Test Organization**:
- Tests are co-located with source files (e.g., `Tesla/test_manage_power.py`)
- Use pytest with asyncio support for async components
- Test paths are configured in `pyproject.toml` (`testpaths`); NodeCheck is not among them
- **Note**: NodeCheck tests run in isolation (separate pytest invocation) due to subprocess management patterns

**Running Tests**:
```bash
# All tests
make test

# Specific module tests
uv run python -m pytest Tesla/test_manage_power.py -v
uv run python -m pytest August/test_august_client.py -v
uv run python -m pytest SamsungFrame/test_samsung_client.py -v

# Specific test class
uv run python -m pytest RachioFlume/test_integration.py::TestRachioClient -v

# Specific test function
uv run python -m pytest Tesla/test_manage_power.py::TestBatteryHistory::test_init -v

# NodeCheck runs in isolation (its own pytest invocation)
uv run pytest NodeCheck
```

## Rules
- **Never `patch()` production code.** If a test needs to mock a subprocess/HTTP call, refactor the production code to accept the dependency as a parameter (factory or client). RingSecurity's `check_devices(ring_factory=...)` is the reference pattern.
- **Module-level `cfg = get_config()` binds at import.** `get_config()` caches a singleton, so patching `get_config` after the module is imported changes nothing. Inject config as a parameter; if a legacy test must patch, patch the bound name (`module.cfg`), never the factory.
- **Test labels are neutral** (`"Controller"`, `"Zone A"`). Never copy a device name, zone label, or any other value from `config/local.yaml` into a test or fixture — those are household identifiers, and the CI denylist scan fails the PR on them.
- **Fake sidecars via `sh` scripts** for subprocess boundaries. `.chmod(0o755)` + write a shebang + parametrize exit codes and stdout. Zero mocking, real subprocess semantics. See `RingBeams/test_beams_manager.py`.
- **Property tests use `hypothesis`** (a dev dependency) for logic that must hold over any sequence of inputs: state a rule, generate the sequences, and drive time through the injected clock. `Tesla/test_manage_power_properties.py` is the reference. After writing one, break the production line it guards and confirm it goes red.
- **Separate deterministic assertions** (exact values, structural matches) from anything that depends on wall-clock time or network state. Freeze time via fixtures if needed.
