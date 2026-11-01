# NEW — shared "what does this machine look like right now" snapshot, used at
# enrollment (wizard.py) and on every check-in (main.py, for the device-info
# refresh flag)

"""
Factored out of wizard.py, which used to build this dict inline for the
one-time /device/enroll payload. Needed a second call site: the admin-
triggered device-info refresh (profile page "Refresh device info" button)
works as a request-flag, not a push — the agent has no listening port by
design (onboarding_flow.md's push-only model), so the server can't ask it
for anything directly. Instead: Device.info_refresh_requested is set
server-side, and the agent includes a snapshot in EVERY /logs/ingest call
regardless (cheap local lookups, no extra request) — the server only
applies it (and clears the flag) when a refresh was actually pending. See
routes/logs.py's ingest_logs for the server-side half.
"""

import getpass
import platform
import socket


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "unknown"


def device_info_snapshot() -> dict:
    return {
        "hostname": platform.node() or socket.gethostname(),
        "username": getpass.getuser(),
        "os_info": platform.platform(),
        "ip_address": _local_ip(),
    }
