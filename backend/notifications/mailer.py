# NEW — sends the Reasoning Core trigger notification email. The only
# place this project ever sends outbound mail; nothing anywhere reads
# incoming mail (send-only, by design -- see this module's own docstring
# below for what that means concretely).

"""
Called from backend/reasoning/worker.py's _process_one(), in BOTH of its
branches -- a successful two-pass judgment, and the graceful-failure case
(LM Studio unreachable or its output failed validation, result is None).
Reuses _reasoning_trigger_fires()'s exact upward-crossing-into-high/
critical condition (agent_logic/analyzer.py) by construction: this only
ever runs from the one place that condition already enqueues a reasoning
trigger, never a separate threshold check of its own.

Send-only, no reply path: this module only ever calls smtplib to SEND.
There is no code anywhere in this project that connects to an inbox,
polls IMAP/POP3, or processes a reply in any way -- not here, not
elsewhere. No Reply-To header is set (there's nothing this app could
point it at that wouldn't itself be misleading, since it's the COMPANY's
own mail account sending, not one litds controls) -- instead the email
body says plainly that replies aren't monitored.

Every failure mode here (no SMTP config resolvable, no opted-in
recipients, a bad credential, a network error mid-send) is caught and
logged, never raised -- a notification failing must never take down the
reasoning worker's loop or block the judgment it's reporting on, same
defensive posture reasoning_loop() already applies around _process_one()
itself.
"""

import smtplib
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from backend.database.db import SessionLocal
from backend.models.admin import Admin
from backend.models.alerts import Alert
from backend.models.company import Company
from backend.models.devices import Device
from backend.models.reasoning import ReasoningJudgment
from backend.notifications.smtp_resolver import record_send_result, resolve_smtp_config
from backend.reports.alert_report import build_alert_report_pdf, build_deterministic_alert_report_pdf

_NO_REPLY_NOTE = (
    "\n\n---\nThis is an automated notification from litds. "
    "Replies to this address are not monitored."
)

# Subject-line labels for the three trigger types (agent_logic/
# analyzer.py's trigger_reason) -- without this, a second or third email
# about the same device in quick succession (continued_escalation) or an
# unusual-but-not-high-severity one (sharp_delta) would read as a
# confusing duplicate rather than the meaningful "still climbing" / "this
# jump itself is the signal" it actually is.
_TRIGGER_REASON_LABELS = {
    "new_crossing": None,  # no suffix -- the ordinary/expected case, subject stays as-is
    "sharp_delta": "sharp increase",
    "continued_escalation": "continued escalation",
}


def _recipients(db, company_id: int) -> list[Admin]:
    """Opted-in admin/manager accounts only -- never the owner (see
    models/admin.py's email/email_notifications_enabled docstring: the
    owner account is deliberately excluded from this feature entirely,
    same reasoning as it being refused a linked device)."""
    return (
        db.query(Admin)
        .filter(
            Admin.company_id == company_id,
            Admin.is_active.is_(True),
            Admin.role != "owner",
            Admin.email_notifications_enabled.is_(True),
            Admin.email.isnot(None),
        )
        .all()
    )


def _build_message(
    *, from_addr: str, to_addr: str, subject: str, body: str, pdf_bytes: bytes, pdf_filename: str
) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(MIMEText(body + _NO_REPLY_NOTE, "plain"))
    attachment = MIMEApplication(pdf_bytes, _subtype="pdf")
    attachment.add_header("Content-Disposition", "attachment", filename=pdf_filename)
    msg.attach(attachment)
    return msg


def send_trigger_notification(item: dict, judgment: ReasoningJudgment | None) -> None:
    """item: the exact dict enqueue_reasoning_trigger() queued (company_id,
    device_id, alert_id, trigger_risk_score, trigger_risk_level, context).
    judgment: the ReasoningJudgment just created, or None if the Reasoning
    Core failed for this trigger -- decides which report/body gets built,
    not whether an email gets sent at all (a genuine critical event must
    never go unnotified just because the LLM layer was down)."""
    from backend.core.runtime import EXTERNAL_SERVICES
    if not EXTERNAL_SERVICES:
        return
    db = SessionLocal()
    try:
        smtp_config = resolve_smtp_config(db, item["company_id"])
        if smtp_config is None:
            print(f"[notifications] no usable SMTP config (company or fallback) for company {item['company_id']} -- notification skipped")
            return

        recipients = _recipients(db, item["company_id"])
        if not recipients:
            print(f"[notifications] no opted-in recipients for company {item['company_id']} -- notification skipped")
            return

        device = db.query(Device).filter(Device.device_id == item["device_id"]).first()
        company = db.query(Company).filter(Company.company_id == item["company_id"]).first()
        alert = db.query(Alert).filter(Alert.id == item["alert_id"]).first() if item["alert_id"] else None
        if device is None or company is None:
            print(f"[notifications] device or company vanished before notification could be sent (device_id={item['device_id']}) -- skipped")
            return

        employee_label = device.label or device.hostname
        reason_label = _TRIGGER_REASON_LABELS.get(item.get("trigger_reason"))
        reason_suffix = f" ({reason_label})" if reason_label else ""

        if judgment is not None:
            subject = f"[litds] {judgment.trigger_risk_level} risk alert -- {employee_label}{reason_suffix}"
            body = judgment.final_explanation
            pdf_bytes = build_alert_report_pdf(judgment, alert, device, company.company_name, decisions=[])
        else:
            subject = f"[litds] {item['trigger_risk_level']} risk alert -- {employee_label} (AI analysis unavailable){reason_suffix}"
            anomalies = item["context"].get("anomalies") or []
            anomaly_text = "; ".join(f"{a.get('type', '?')}: {a.get('message', '')}" for a in anomalies) or "no single anomaly this window -- aggregate risk score crossed the threshold from accumulated/decaying prior signals"
            body = (
                f"{employee_label} ({device.hostname}) crossed into {item['trigger_risk_level']} risk "
                f"(score {round(item['trigger_risk_score'])}/100).\n\n"
                f"Triggering anomalies: {anomaly_text}\n\n"
                f"AI Reasoning Core analysis was not available for this event -- the local LLM service "
                f"was unreachable at the time. See the attached report for the full deterministic detail, "
                f"and review this device in the litds dashboard."
            )
            pdf_bytes = build_deterministic_alert_report_pdf(
                item["context"], item["trigger_risk_score"], item["trigger_risk_level"],
                datetime.now(timezone.utc), alert, device, company.company_name,
            )

        pdf_filename = f"litds-alert-report-{device.hostname}.pdf".replace(" ", "_")

        # This block specifically is what record_send_result below tracks
        # -- a bad credential (or any other failure connecting/authenticating/
        # sending) becomes visible on the Company Profile SMTP status line
        # (GET /company/smtp), not only in this server log line, which is
        # otherwise the only place a failure like this showed up before.
        try:
            server = smtplib.SMTP(smtp_config.host, smtp_config.port, timeout=15)
            try:
                server.ehlo()
                if server.has_extn("STARTTLS"):
                    server.starttls()
                    server.ehlo()
                # Opportunistic, same as STARTTLS above -- every real
                # provider (Gmail, Office365, etc.) advertises AUTH on the
                # ports this is meant for, so this is a no-op change for
                # the real case, but blindly calling login() against a
                # server that never advertised AUTH raises
                # SMTPNotSupportedError instead of sending -- confirmed
                # live against a local test relay with no AUTH support
                # before this check existed.
                if smtp_config.username and server.has_extn("AUTH"):
                    server.login(smtp_config.username, smtp_config.password)

                for admin in recipients:
                    msg = _build_message(
                        from_addr=smtp_config.username,
                        to_addr=admin.email,
                        subject=subject,
                        body=body,
                        pdf_bytes=pdf_bytes,
                        pdf_filename=pdf_filename,
                    )
                    server.sendmail(smtp_config.username, [admin.email], msg.as_string())
                    print(f"[notifications] sent trigger notification to {admin.email} via {smtp_config.source} SMTP config (company {item['company_id']})")
            finally:
                server.quit()
        except Exception as e:
            record_send_result(db, item["company_id"], smtp_config.source, success=False, error=str(e))
            raise
        else:
            record_send_result(db, item["company_id"], smtp_config.source, success=True, error=None)

    except Exception as e:
        print(f"[notifications] failed to send trigger notification for device {item.get('device_id')}: {e}")
    finally:
        db.close()


def send_employee_notification(db, *, company_id: int, to_email: str, message: str) -> tuple[str, str | None]:
    """The admin-triggered, manual-only "Notify Employee" alert
    (routes/device.py's notify_employee) -- a deliberately different
    shape from send_trigger_notification above, not a variant of it:
    plain text only (no PDF/attachment of any kind -- avoids tipping off
    detection detail or sending unreviewed evidence straight to the
    subject, a scope decision made explicitly for this feature), and
    synchronous with a real (status, error) return rather than fire-and-
    forget, since the calling route needs the actual outcome to both
    answer the admin's request and write the audit row -- unlike the
    trigger-notification path (called from the background reasoning
    worker, nothing there is waiting on a result).

    The message itself is the admin's own text verbatim (the pre-filled
    default, possibly edited) -- this function never composes or alters
    it, only sends exactly what it's given. No _NO_REPLY_NOTE footer
    appended either: the default text this feature ships with already
    ends with its own "replies aren't monitored" sentence, so appending
    the other footer would just duplicate it for an admin who kept the
    default, and be actively wrong for one who deliberately edited it out.

    Returns ("success", None) or ("failed", "<error>") -- never raises;
    every failure mode (no SMTP config, a bad credential, a network
    error) becomes a returned failure the caller records, same "never
    silently drop" discipline as the trigger-notification path, just
    surfaced as a return value instead of a log line since there's a
    real caller waiting here."""
    from backend.core.runtime import EXTERNAL_SERVICES
    if not EXTERNAL_SERVICES:
        return "failed", "External services disabled in the release demo"
    smtp_config = resolve_smtp_config(db, company_id)
    if smtp_config is None:
        return "failed", "No SMTP is configured for this company (and no local fallback is set up)."

    try:
        server = smtplib.SMTP(smtp_config.host, smtp_config.port, timeout=15)
        try:
            server.ehlo()
            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo()
            if smtp_config.username and server.has_extn("AUTH"):
                server.login(smtp_config.username, smtp_config.password)

            msg = MIMEText(message, "plain")
            msg["From"] = smtp_config.username
            msg["To"] = to_email
            msg["Subject"] = "A message from your employer's monitoring system"
            server.sendmail(smtp_config.username, [to_email], msg.as_string())
            print(f"[notifications] sent employee notification to {to_email} via {smtp_config.source} SMTP config (company {company_id})")
        finally:
            server.quit()
    except Exception as e:
        record_send_result(db, company_id, smtp_config.source, success=False, error=str(e))
        return "failed", str(e)

    record_send_result(db, company_id, smtp_config.source, success=True, error=None)
    return "success", None
