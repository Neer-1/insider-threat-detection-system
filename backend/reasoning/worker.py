# NEW — background task that consumes triggered reasoning requests, fully decoupled
# from backend/scheduler.py's real-time detection loop

"""
This is the piece that makes the ~10s/pass LM Studio latency safe to have
in this project at all. agent_logic/analyzer.py's trigger check does one
cheap, synchronous thing when a device crosses into high/critical:
enqueue_reasoning_trigger() puts a small dict on an in-memory
asyncio.Queue and returns immediately — no LLM call happens on the
scheduler's thread of execution. reasoning_loop() (started in main.py's
lifespan, same pattern as backend/scheduler.py's analysis_loop) drains
that queue on its own pace, entirely independent of the 10-second
real-time cadence.

The queue is in-process and in-memory, not DB-backed, deliberately: a
judgment lost on a server restart before it's processed isn't a real
loss (the deterministic Alert/risk score it was reasoning about already
stands on its own) — see core/config.py's "AI Reasoning Core" section.
"""

import asyncio

from backend.core.config import REASONING_MODEL, REASONING_QUEUE_BACKLOG_WARN_THRESHOLD
from backend.database.db import SessionLocal
from backend.models.reasoning import ReasoningJudgment
from backend.notifications.mailer import send_trigger_notification
from backend.reasoning.core import run_two_pass_judgment

_queue: asyncio.Queue = asyncio.Queue()
_backlog_warned = False


def enqueue_reasoning_trigger(item: dict) -> None:
    """item: {"company_id", "device_id", "alert_id", "trigger_risk_score",
    "trigger_risk_level", "context"}. Called synchronously from
    analyzer.py — put_nowait() never blocks or awaits, so this is safe to
    call from a plain (non-async) function running on the event loop
    thread, which analyze_device_window() is."""
    global _backlog_warned
    _queue.put_nowait(item)

    depth = _queue.qsize()
    if depth >= REASONING_QUEUE_BACKLOG_WARN_THRESHOLD:
        if not _backlog_warned:
            print(
                f"[reasoning] queue backlog reached {depth} pending judgment(s) — LM Studio processes "
                f"one at a time, so triggers are queuing up faster than they're being reasoned about. "
                f"Not a crash, but judgments will lag behind real-time until this drains."
            )
            _backlog_warned = True
    else:
        _backlog_warned = False


async def _process_one(item: dict) -> None:
    result = await run_two_pass_judgment(item["context"])
    if result is None:
        print(
            f"[reasoning] no judgment produced for device {item['device_id']} "
            f"(LM Studio unreachable or output failed validation) — skipping, deterministic alert stands as-is"
        )
        # Notification is decoupled from Reasoning Core success on purpose
        # (core/config.py's "AI Reasoning Core" section, notifications/
        # mailer.py's own docstring): a genuine critical event must never
        # go unnotified just because the LLM layer was down. smtplib is
        # synchronous I/O -- run in a thread so a slow/unreachable SMTP
        # server can't stall this event loop the same way a blocking LLM
        # call would (see reasoning/client.py's own httpx-over-requests
        # reasoning for the identical concern).
        await asyncio.to_thread(send_trigger_notification, item, None)
        return

    db = SessionLocal()
    try:
        judgment = ReasoningJudgment(
            company_id=item["company_id"],
            device_id=item["device_id"],
            alert_id=item["alert_id"],
            trigger_risk_score=item["trigger_risk_score"],
            trigger_risk_level=item["trigger_risk_level"],
            context_snapshot=item["context"],
            model_used=REASONING_MODEL,
            **result,
        )
        db.add(judgment)
        db.commit()
        db.refresh(judgment)
        print(f"[reasoning] judgment ready for device {item['device_id']}: recommendation={result['final_recommendation']}")
    finally:
        db.close()

    await asyncio.to_thread(send_trigger_notification, item, judgment)


async def reasoning_loop() -> None:
    """Runs forever until cancelled (main.py cancels it on shutdown, same
    as analysis_loop). No fixed polling interval needed — Queue.get()
    blocks until an item is actually available, so this is idle (no CPU,
    no LM Studio calls) whenever nothing has triggered."""
    while True:
        item = await _queue.get()
        try:
            await _process_one(item)
        except Exception as e:
            print(f"[reasoning] unexpected error processing trigger for device {item.get('device_id')}: {e}")
        finally:
            _queue.task_done()
