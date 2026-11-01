# NEW — installable agent entrypoint: run wizard once, then loop of collect + send

"""
1. Run the wizard once (only if no local config exists yet).
2. Poll for approval (GET /device/{id}/status) until a device_token is
   granted — an admin has to explicitly approve a device before it's
   allowed to send anything (routes/device.py, routes/logs.py). An admin
   REJECTING the request instead is the other real outcome here (routes/
   device.py's reject_device) -- wait_for_approval below ends the wizard
   with a clear message rather than polling forever, since "approved" was
   never going to happen for this particular request.
3. Collect + send loop: buffer everything locally first, then attempt to
   flush the buffer on every cycle. Any failed send — offline, server
   down, device not approved yet — leaves events queued for the next
   attempt (see buffer.py). Deliberately the same code path regardless of
   *why* the send failed: the agent doesn't need to know which one it is,
   it just keeps trying, matching onboarding_flow.md's "when the device is
   no longer connected it will store the logs locally and send it all at
   once once connected."
4. On any cycle where step 3 collected no real activity, a heartbeat
   (event_type="heartbeat") rides along on that same cycle's request
   instead — the server has no way to be told "I'm disconnecting" (no
   listening port on this side to push that through even if it wanted to),
   so a regular, explicit "still here" signal on quiet cycles is what lets
   it infer offline status from staleness with real confidence rather than
   guessing from the presence/absence of real behavioral events, which go
   quiet during ordinary idle periods too. See send_batch's extra_log
   param and collector.py's build_heartbeat_event for why this is
   deliberately NOT run through the same buffer/retry path real events
   get.
"""

import time

import requests

from agent import buffer
from agent.collector import CollectorState, build_heartbeat_event, collect_events
from agent.config import delete_config, load_config, save_config
from agent.device_info import device_info_snapshot
from agent.wizard import run_wizard

STATUS_POLL_INTERVAL_SECONDS = 30
SEND_BATCH_LIMIT = 200


class EnrollmentRejected(Exception):
    """Raised by wait_for_approval when an admin rejects this device's
    pending enrollment -- distinct from a network/offline error (which
    just retries), this is a real, final answer for this specific
    request. Caught in run() below to print the console-native "Request
    rejected... Close" flow this agent has (no GUI -- see wizard.py's own
    docstring for why): a message, then the process exits, which is the
    direct equivalent of a Close button ending the wizard."""


def wait_for_approval(config) -> str:
    """Blocks until the device is approved, returning its device_token,
    or raises EnrollmentRejected if an admin denies the request instead.
    Each poll sends the company code as tenant proof alongside the public
    device ID. The code must remain available until approval completes."""
    while True:
        try:
            response = requests.get(
                f"{config.server_url}/device/{config.device_id}/status",
                headers={"X-Company-Code": config.company_code},
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
            if data["approval_status"] == "approved" and data["device_token"]:
                return data["device_token"]
            if data["approval_status"] == "rejected":
                raise EnrollmentRejected()
        except requests.exceptions.RequestException:
            pass  # offline / server unreachable — just keep retrying

        print(f"Waiting for admin approval... (checking again in {STATUS_POLL_INTERVAL_SECONDS}s)")
        time.sleep(STATUS_POLL_INTERVAL_SECONDS)


def send_batch(config, device_token: str, entries: list, extra_log: dict | None = None) -> bool:
    """Returns True only if the server confirmed receipt — the caller only
    removes entries from the local buffer on a confirmed True, never
    optimistically. Every call includes a fresh device_info snapshot
    (hostname/username/os_info/ip_address) — cheap local lookups, so no
    reason to gate them behind anything. The server only actually applies
    it when Device.info_refresh_requested is set (admin clicked "Refresh
    device info" on the profile page); otherwise it's ignored. This is the
    agent's half of that request-flag design — there's no listening port
    on the employee's device to push a refresh to directly, so "next
    check-in carries current info" is what "refresh" means here.

    Deliberately called every cycle regardless of whether there are any
    entries to send (see run(), below) — an idle machine can genuinely go
    a while with nothing new to report (collector.py only reports NEW
    activity relative to its own baseline), but a device-info refresh
    still needs a real check-in to arrive on, not just whenever the device
    happens to do something. The server skips writing a LogBuffer sync-
    event row when the log list is empty, so this doesn't bloat that table
    with empty rows every cycle.

    extra_log: an optional heartbeat entry (collector.py's
    build_heartbeat_event, run() below) appended to this cycle's outgoing
    batch WITHOUT ever being written to the local buffer or included in
    `ids` — this function already POSTs every single cycle regardless of
    `entries`, so a heartbeat rides along on that same already-happening
    request instead of doubling the agent's network traffic with a second,
    separate call. Deliberately not persisted: if this send fails, the
    heartbeat is just dropped, never queued for a later retry — see
    run()'s own comment on why a buffered/replayed heartbeat would be
    actively misleading rather than useful. `entries` (real, buffered
    activity) keeps its full retry guarantee regardless of whether a
    heartbeat rides along or not."""
    ids = [e[0] for e in entries]
    logs = [e[1] for e in entries]
    if extra_log is not None:
        logs = logs + [extra_log]
    try:
        response = requests.post(
            f"{config.server_url}/logs/ingest",
            json={
                "device_id": config.device_id,
                "device_token": device_token,
                "logs": logs,
                "device_info": device_info_snapshot(),
            },
            timeout=30,
        )
        if response.status_code == 201:
            buffer.remove(ids)
            return True
        return False
    except requests.exceptions.RequestException:
        return False


def run():
    config = load_config()
    if config is None:
        config = run_wizard()

    if not config.device_token:
        try:
            config.device_token = wait_for_approval(config)
        except EnrollmentRejected:
            # Console equivalent of "Request rejected" + a Close button
            # (wizard.py's own docstring explains why this agent is
            # console-only, not a GUI). delete_config() removes the local
            # config for this now-dead request -- the SAME physical
            # device can attempt enrollment again later (routes/
            # device.py's enroll_device resets a rejected row back to
            # "pending" on a fresh /enroll call), which only happens if
            # the next launch has no config to load and re-runs the
            # wizard from scratch.
            print("Request rejected.")
            print("Your admin has denied this device's enrollment request.")
            delete_config()
            raise SystemExit(0)
        save_config(config)

    print(f"Approved. Starting collection (every {config.send_interval_seconds}s)...")
    state = CollectorState()

    while True:
        new_events = collect_events(state)
        buffer.enqueue(new_events)

        pending = buffer.peek_batch(SEND_BATCH_LIMIT)
        # Nothing real collected THIS cycle -- send an explicit "still
        # here" signal (event_type="heartbeat") instead of relying on the
        # server to guess liveness from whatever real activity happens to
        # show up. Real activity already proves liveness on its own (no
        # separate heartbeat needed the moment there's something real to
        # send); this only ever fires on a genuinely quiet cycle.
        #
        # Deliberately built fresh here and passed straight into
        # send_batch's extra_log rather than buffer.enqueue()'d like real
        # events -- a heartbeat that fails to send now and gets queued for
        # later delivery would be actively misleading once replayed: by
        # the time a buffered heartbeat finally reaches the server (device
        # back online), that reconnection itself already proves current
        # liveness far better than an old timestamp ever could, and if the
        # device is STILL offline, the heartbeat never gets there anyway --
        # either way, holding onto it serves no purpose real activity
        # doesn't already serve, at the cost of bloating the local buffer
        # with "still here" spam for the entire duration of an outage.
        heartbeat = build_heartbeat_event() if not new_events else None
        sent = send_batch(config, config.device_token, pending, extra_log=heartbeat)
        # Only print anything when there was actually something to report --
        # an idle cycle with nothing queued still checks in (see send_batch's
        # docstring) but doing so silently, so a quiet machine doesn't spam
        # the console every send_interval_seconds.
        if pending:
            if sent:
                print(f"Sent {len(pending)} events ({buffer.count()} still queued)")
            else:
                print(f"Could not reach server — {buffer.count()} events queued locally")

        time.sleep(config.send_interval_seconds)


if __name__ == "__main__":
    run()
