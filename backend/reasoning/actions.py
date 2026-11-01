# NEW — executes an admin's accept/override decision through the EXISTING Response
# mechanism (models/responses.py, agent_logic/response_engine.py's save_responses)

"""
Deliberately separate from response_engine.py's own risk-level-keyed
action table (core/config.py's REASONING_ACTION_MAP docstring explains
why) — this module is the only thing that ever turns a Reasoning Core
recommendation into a real Response row, and it only ever runs after an
explicit admin decision (routes/reasoning.py). The Reasoning Core itself
never calls this.
"""

from sqlalchemy.orm import Session

from backend.agent_logic.response_engine import save_responses
from backend.core.config import REASONING_ACTION_MAP
from backend.models.responses import Response


def apply_decision(db: Session, alert_id: int | None, recommendation: str, admin_id: int) -> list[Response]:
    """recommendation is one of core/config.py's REASONING_RECOMMENDATIONS
    (the accepted judgment's own final_recommendation, or the admin's
    override choice — routes/reasoning.py validates it's one of the five
    before this is ever called). Returns the Response rows created, which
    is an empty list for "dismiss" (no action, by design) or when there's
    no alert to attach a Response to (see models/reasoning.py's alert_id
    docstring — the aggregate-score trigger doesn't always correspond to
    one specific Alert row; logged here rather than silently dropped)."""
    actions = REASONING_ACTION_MAP.get(recommendation, [])
    if not actions:
        return []
    if alert_id is None:
        print(
            f"[reasoning] admin {admin_id} chose '{recommendation}' but this judgment has no linked alert -- "
            f"decision is still recorded on the judgment itself, but no Response row could be created"
        )
        return []
    return save_responses(db, alert_id, actions, triggered_by_admin_id=admin_id)
