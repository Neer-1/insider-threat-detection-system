# NEW — first-run setup: accepts pasted server address + company ID, calls POST /device/enroll, saves local config

"""
Console-based, not a GUI — deliberate: a GUI (even a lightweight stdlib
tkinter one) is unrequested complexity for something that only ever needs
to accept two pasted strings.

REVISED (was: company code only, with the server address baked into the
executable at PyInstaller build time via packaging/agent/build_agent.ps1's
-ServerUrl parameter -- see git history / config.py's own comment for that
version's reasoning). That meant a distinct .exe had to be built per
deployment, which doesn't scale past a single-admin demo: every real
deployment needs its own build step with its own server address typed in
correctly, by someone who has PyInstaller and this source tree available,
before a single employee device can use it. Reversed for exactly the
opposite property Step 1 of this change asks for: one single, generic,
already-built .exe that works on any device, asking for both the server
address and the company code the first time it's run, then never again.
The wizard now prompts for both -- see run_wizard() below. config.py's
DEFAULT_SERVER_URL still exists as a suggested default (pre-filled, not
silently used) purely so local dev/testing (LITDS_SERVER_URL env var)
doesn't require retyping localhost every time; every real end-user still
gets an explicit prompt with nothing assumed on their behalf.
"""

import hashlib
import platform
import uuid

import requests

from agent.config import AgentConfig, DEFAULT_SEND_INTERVAL_SECONDS, DEFAULT_SERVER_URL, save_config
from agent.device_info import device_info_snapshot


def _prompt_server_url() -> str:
    """Prompts for the server address, pre-filling DEFAULT_SERVER_URL
    (config.py's LITDS_SERVER_URL env var, or empty) as a suggested value
    the person can accept by just pressing Enter -- not a silent fallback,
    since an end user with no env var set sees an empty suggestion and
    must type something real. Accepts a bare host:port too (e.g.
    "192.168.1.10:8000") and normalizes it to a full URL -- an admin
    reading this off `ipconfig` has no reason to know it needs an
    "http://" prefix, and typing it wrong here is a real support burden
    this can trivially absorb instead. Strips any trailing slash so
    f"{server_url}/device/enroll" (below) and every other call site never
    ends up with an accidental double slash."""
    suggestion = DEFAULT_SERVER_URL
    prompt = f"Server address [{suggestion}]: " if suggestion else "Server address: "
    while True:
        raw = input(prompt).strip()
        if not raw:
            raw = suggestion
        if not raw:
            print("A server address is required.")
            continue
        if not raw.startswith(("http://", "https://")):
            raw = f"http://{raw}"
        return raw.rstrip("/")


def device_fingerprint() -> str:
    """A stable identifier for this physical machine, independent of the
    device_id the server assigns — this is what routes/device.py's
    /enroll uses to recognise "this is the same machine re-enrolling" and
    update its existing row instead of creating a duplicate. Built from the
    hostname plus the machine's MAC address (uuid.getnode()), hashed so
    the raw MAC never leaves the device.

    Not blocking, but worth knowing: uuid.getnode() falls back to a
    randomly-generated value on machines where it can't determine a real
    hardware MAC address (some VMs, some network configurations) — on
    those systems the fingerprint may not actually be stable across runs.
    Separately, changing the machine's hostname changes the fingerprint
    too, since it's part of the hash input — a renamed machine would be
    treated as a brand-new device re-enrolling from scratch rather than
    being recognised as the same one under its old name."""
    raw = f"{platform.node()}-{uuid.getnode()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def run_wizard() -> AgentConfig:
    print("=" * 60)
    print("  litds agent - first-time setup")
    print("=" * 60)
    print("This only runs once. Ask your admin for the server address and")
    print("company code before continuing.")
    print()

    server_url = _prompt_server_url()

    print()
    print("Paste the company code your admin gave you, then press Enter.")
    company_code = input("Company code: ").strip()
    while not company_code:
        company_code = input("Company code (required): ").strip()

    payload = {
        "company_code": company_code,
        "device_fingerprint": device_fingerprint(),
        **device_info_snapshot(),
    }

    print("Connecting to server...")
    try:
        response = requests.post(f"{server_url}/device/enroll", json=payload, timeout=15)
    except requests.exceptions.RequestException as e:
        # A typo'd/unreachable server address is a real, expected failure
        # mode now that this is free-typed input rather than a value baked
        # in at build time and guaranteed correct -- a raw traceback here
        # would be a poor first impression for what's supposed to be a
        # one-screen setup. Deliberately not retried/looped: unlike
        # wait_for_approval's "keep trying, we know this address is
        # right, just wait for an admin" case, a failure THIS early most
        # likely means the address itself is wrong, so asking the person
        # to re-run and re-check it (rather than silently retrying against
        # something they may have mistyped) is the more useful response.
        raise SystemExit(
            f"Could not reach '{server_url}' -- {e}\n"
            "Double-check the server address with your admin (including the port, "
            "e.g. http://192.168.1.10:8000) and run this program again."
        )

    if response.status_code == 401:
        raise SystemExit("That company code wasn't recognised. Check it with your admin and try again.")
    response.raise_for_status()

    data = response.json()
    config = AgentConfig(
        server_url=server_url,
        company_code=company_code,
        device_fingerprint=payload["device_fingerprint"],
        device_id=data["device_id"],
        device_token=None,  # granted once an admin approves this device — see main.py
        send_interval_seconds=DEFAULT_SEND_INTERVAL_SECONDS,
    )
    save_config(config)

    print("Setup complete. Waiting for your admin to approve this device...")
    return config
