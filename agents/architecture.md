# Architecture

Part of the agent guide: [AGENTS.md](../AGENTS.md).

## Module Organization
This is a **modular IoT home automation system** with independent components that share common utilities:

- **`lib/`**: Shared utilities (config, networking, notifications, logging, secret I/O, file lock)
- **Home / IoT modules**: August, NetworkCheck, NodeCheck, RachioFlume, RingBeams, RingSecurity, SamsungFrame, Tesla
- **AI / ML modules**: BimpopAI (RAG system), GarageCheck (computer vision), VoiceNotes (local STT)
- **Ops modules**: PersonalCalSync (Google Apps Script)
- **Formal models**: formal (Quint specs of concurrency designs)
- **Client / adjacent**: NoShorts (iOS app), AugustUnlock (iOS app), VSCodeSidebarNotes (VS Code / Cursor extension), ScreenShare (AppleScript launcher app), BrowserAlert, GPXParser

## Key Architectural Patterns

**Shared Library Pattern**: All modules use utilities from `lib/`:
- `lib/config.py` - OmegaConf-based hierarchical YAML configuration system
- `lib/logger.py` - Standardized logging
- `lib/MyPushover.py`, `lib/Mailer.py` - Notification services
- `lib/NetHelpers.py` - Network utilities

**Independent Modules**: Each Python component directory (Tesla/, RachioFlume/, etc.) operates independently but follows consistent patterns:
- Main script with CLI interface
- README.md with component-specific documentation
- Test files following pytest conventions
- Pydantic models for data validation

**Git Submodules**: External dependencies like TeslaPy are managed as submodules in `lib/TeslaPy/`

**Module isolation**: each component can be developed independently. **Shared utilities**: prefer extending `lib/` over duplicating code.

## Key dependencies

- **Python 3.13+**: Required for async features and modern typing
- **uv**: Package manager for fast installs and dependency resolution
- **pydantic**: Data validation across all modules
- **pytest + asyncio**: Testing framework with async support
