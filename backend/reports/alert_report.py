# NEW — per-alert PDF: routes/reasoning.py's report.pdf endpoint (judgment
# always present) AND notifications/mailer.py's trigger-notification
# attachment (judgment present when the Reasoning Core succeeded, absent
# when LM Studio was unreachable at trigger time). Same document either
# way -- the judgment-optional path is an extension of this one report
# type, not a second one.

from datetime import datetime

from backend.core.config import REASONING_RECOMMENDATION_LABELS
from backend.models.alerts import Alert
from backend.models.devices import Device
from backend.models.reasoning import ReasoningJudgment
from backend.models.reasoning_decision import ReasoningDecision
from backend.reports.pdf_builder import bold_line, bullet, empty_note, format_mauritius, label_value, new_report, paragraph, section_title, to_bytes


def _render_trigger_section(pdf, context: dict, trigger_risk_score: float, trigger_risk_level: str, alert: Alert | None) -> None:
    """"What Triggered This" -- judgment-agnostic: everything it reads
    (anomalies, active risk components) comes from the deterministic
    context/evidence bundle (agent_logic/reasoning/core.py's
    gather_context(), the same dict shape whether or not a
    ReasoningJudgment ever got created from it), not from judgment fields.
    Shared by both build_alert_report_pdf (a real judgment exists) and
    build_deterministic_alert_report_pdf (it doesn't) so this section
    reads identically in either report."""
    section_title(pdf, "What Triggered This")
    label_value(pdf, "Risk level at trigger", f"{trigger_risk_level} ({round(trigger_risk_score)}/100)")
    if alert is not None:
        label_value(pdf, "Linked alert", alert.title)
        label_value(pdf, "Alert status", alert.status)
    pdf.ln(2)

    anomalies = context.get("anomalies") or []
    if anomalies:
        bold_line(pdf, "Anomalies in the triggering window:")
        for a in anomalies:
            bullet(pdf, f"[{a.get('type', '?')}] {a.get('message', '')} (severity {a.get('severity', '?')})")
    else:
        empty_note(pdf, "No anomaly in this specific window -- the aggregate risk score crossed the threshold from accumulated/decaying prior signals.")

    components = context.get("risk_components") or []
    if components:
        pdf.ln(2)
        bold_line(pdf, "Active risk components at trigger time:")
        for c in components:
            score = c.get("score")
            score_text = f"{score:.1f}" if isinstance(score, (int, float)) else str(score)
            bullet(pdf, f"{c.get('anomaly_type', '?')}: {score_text}")


def build_alert_report_pdf(
    judgment: ReasoningJudgment,
    alert: Alert | None,
    device: Device,
    company_name: str,
    decisions: list[ReasoningDecision],
) -> bytes:
    evidence = judgment.context_snapshot or {}
    employee_label = device.label or device.hostname

    pdf = new_report(
        "AI Reasoning Core Report",
        f"{company_name} -- {employee_label} ({device.hostname})",
    )

    label_value(pdf, "Triggered at", format_mauritius(judgment.triggered_at))
    _render_trigger_section(pdf, evidence, judgment.trigger_risk_score, judgment.trigger_risk_level, alert)

    section_title(pdf, "AI Assessment")
    paragraph(pdf, judgment.final_explanation)
    label_value(pdf, "Model used", judgment.model_used)
    if judgment.final_confidence is not None:
        label_value(pdf, "Confidence", f"{round(judgment.final_confidence * 100)}%")
    if judgment.critic_changed_judgment:
        paragraph(
            pdf,
            "Note: a second-opinion review pass revised the initial assessment before this was shown to an admin.",
            italic=True, size=9.5,
        )

    section_title(pdf, "Recommendation")
    recommendation_label = REASONING_RECOMMENDATION_LABELS.get(judgment.final_recommendation, judgment.final_recommendation)
    bold_line(pdf, recommendation_label, size=12)
    pdf.ln(4)

    section_title(pdf, "Decision")
    if not decisions:
        empty_note(pdf, "Awaiting admin review as of the time this report was generated -- no decision has been made yet.")
    else:
        for d in sorted(decisions, key=lambda d: d.decided_at or d.id):
            admin_name = d.admin.username if d.admin else "unknown admin"
            action_label = REASONING_RECOMMENDATION_LABELS.get(d.action_value, d.action_value) if d.action_value else None
            line = f"{format_mauritius(d.decided_at)} -- {admin_name} chose: {d.decision}"
            if action_label:
                line += f" ({action_label})"
            bullet(pdf, line)
            if d.dismiss_reason:
                bullet(pdf, f'Reason: "{d.dismiss_reason}"', indent="  ")

    return to_bytes(pdf)


def build_deterministic_alert_report_pdf(
    context: dict,
    trigger_risk_score: float,
    trigger_risk_level: str,
    triggered_at: datetime,
    alert: Alert | None,
    device: Device,
    company_name: str,
) -> bytes:
    """The no-judgment counterpart to build_alert_report_pdf -- LM Studio
    was unreachable (or its output failed validation) at the moment this
    device crossed into high/critical, so no ReasoningJudgment row exists
    at all (backend/reasoning/worker.py's graceful-failure path). A
    genuine critical event must never go unnotified just because the LLM
    layer happened to be down -- this is what notifications/mailer.py
    attaches instead, built from the exact same deterministic context
    gather_context() already produced for the (aborted) LLM call, so
    nothing about the underlying detection data is missing, just the AI's
    own explanation/recommendation on top of it."""
    employee_label = device.label or device.hostname

    pdf = new_report(
        "Risk Alert Report (AI analysis unavailable)",
        f"{company_name} -- {employee_label} ({device.hostname})",
    )

    label_value(pdf, "Triggered at", format_mauritius(triggered_at))
    _render_trigger_section(pdf, context, trigger_risk_score, trigger_risk_level, alert)

    section_title(pdf, "AI Assessment")
    empty_note(
        pdf,
        "AI Reasoning Core analysis was not available for this event -- the local LLM service was "
        "unreachable (or its output failed validation) at the time this device crossed into "
        "high/critical risk. This report reflects the deterministic risk-scoring and rule-based "
        "detection data above only; no AI-generated explanation or recommendation exists for this event.",
    )

    return to_bytes(pdf)
