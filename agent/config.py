# NEW — stores this device's server URL + company ID + assigned device ID after enrollment

"""
Local agent configuration, persisted to ~/.litds-agent/config.json.

REVISED — SERVER_URL used to be deliberately excluded from the wizard
prompt, baked into the executable at PyInstaller build time instead (see
git history / packaging/agent/build_agent.ps1's old -ServerUrl parameter).
That meant a distinct .exe per deployment, which doesn't scale: one single,
generic, already-built .exe working on any device is the actual goal, so
the wizard now prompts for the server address alongside the company code
(wizard.py's run_wizard/_prompt_server_url) and persists whatever was
entered here, in AgentConfig.server_url — read back by load_config() on
every subsequent run, never re-prompted once saved.

DEFAULT_SERVER_URL below is now only ever a SUGGESTED value the wizard
prompt pre-fills (accept with Enter, or type over it) — never a silent
fallback a real deployment would end up using without anyone actually
choosing it. Its only real source is LITDS_SERVER_URL (an env var, for
local dev/testing convenience -- so a developer running the agent against
a local server doesn't have to retype "http://localhost:8000" on every
fresh config wipe); with nothing set, the wizard prompt is simply empty
and requires a real typed answer, which is the correct behavior for an
end user who must always provide-something real anyway.

SEND_INTERVAL_SECONDS follows the same env-var-only pattern (never
wizard-prompted, per onboarding_flow.md) — LITDS_SEND_INTERVAL_SECONDS,
clamped to [10, 30]. Not the same knob as backend/core/config.py's
ANALYSIS_INTERVAL_SECONDS (how often the server re-scores a device's
recent activity) — this is only how often the agent flushes collected
events off the device. Turning this down makes events reach the server
sooner; the server-side scheduler now runs independently every ~10s
regardless of this setting.
"""

import json
import os
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

DEFAULT_SERVER_URL = os.environ.get("LITDS_SERVER_URL") or ""


def _default_send_interval() -> int:
    try:
        raw = int(os.environ.get("LITDS_SEND_INTERVAL_SECONDS", 15))
    except ValueError:
        raw = 15
    return max(10, min(30, raw))


DEFAULT_SEND_INTERVAL_SECONDS = _default_send_interval()

CONFIG_DIR = Path.home() / ".litds-agent"
CONFIG_PATH = CONFIG_DIR / "config.json"
BUFFER_DB_PATH = CONFIG_DIR / "buffer.db"


@dataclass
class AgentConfig:
    server_url: str
    company_code: str
    device_fingerprint: str
    device_id: str  # Device.public_id, assigned at enrollment
    device_token: Optional[str] = None  # assigned at approval — see wizard.py / main.py
    # Default kept here (not just in main.py) so an old config.json saved
    # before this field existed still loads fine via AgentConfig(**data) —
    # missing key falls back to this default instead of a TypeError.
    send_interval_seconds: int = 15


def load_config() -> Optional[AgentConfig]:
    if not CONFIG_PATH.exists():
        return None
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return AgentConfig(**data)


def _restrict_permissions(path: Path) -> None:
    """Owner-read/write-only — config.json holds device_token in plaintext
    (per §4.12's "secure configuration management"), so it shouldn't be
    readable by other local accounts on a shared machine. Best-effort: a
    failure here prints a warning rather than crashing the agent, since an
    agent that can't run at all is worse than one running with slightly
    looser file permissions than intended."""
    try:
        if sys.platform == "win32":
            # os.chmod can't express POSIX-style owner-only restriction on
            # Windows (NTFS uses ACLs, not rwx bits) — icacls is the actual
            # mechanism, invoked as a subprocess rather than adding a
            # pywin32 dependency just for this.
            username = os.environ.get("USERNAME", "")
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{username}:F"],
                capture_output=True, check=True,
            )
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except Exception as e:
        print(f"Warning: could not restrict permissions on {path}: {e}")


def save_config(config: AgentConfig) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
    _restrict_permissions(CONFIG_PATH)


def delete_config() -> None:
    """Called when main.py's wait_for_approval sees this device was
    rejected -- a rejected enrollment's local config (an approval-less
    device_id it'll never get a token for) is useless going forward, and
    leaving it in place would silently break "try again": the next run
    would just resume polling the same rejected device_id instead of
    re-enrolling. Removing it means the next launch has no config to
    load, so main.py's run() naturally falls through to run_wizard()
    again, hitting POST /device/enroll fresh -- which is what actually
    resets a rejected row back to "pending" server-side (routes/
    device.py's enroll_device)."""
    if CONFIG_PATH.exists():
        CONFIG_PATH.unlink()
