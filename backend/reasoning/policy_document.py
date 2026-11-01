# NEW — company bylaws/policy PDF -> cleaned Markdown conversion, section
# splitting, and simple keyword-based relevance selection for the
# Reasoning Core's evidence bundle (reasoning/core.py's gather_context()).

"""
Pure read-only input to the LLM's prompt -- nothing here ever touches
Device.current_risk_score, DeviceRiskComponent, or any part of
agent_logic/analyzer.py's deterministic scoring path. Same boundary
gather_context() already holds for everything else it assembles.

Conversion (convert_pdf_to_markdown) runs ONCE, at upload time
(routes/company.py) -- the result is stored in CompanyPolicyDocument and
never re-converted. Section selection (select_relevant_excerpt) runs
fresh on every judgment that has a policy document available, re-parsing
the stored Markdown rather than caching a pre-split version -- cheap
(milliseconds on realistic document sizes) and keeps a single source of
truth instead of two representations that could drift out of sync.

No embeddings, no vector search -- deliberately. See the project's own
design discussion (docs/known_limitations.md) for the reasoning: a
formally-sectioned bylaws document (numbered articles/clauses, the norm
for this document type) is exactly the case simple keyword-count
selection handles well, and the loaded model's real 131072-token context
window (confirmed live against LM Studio) means fit was never actually
the constraint -- this exists for latency and relevance, not because a
realistic document wouldn't fit whole.
"""

import io
import re
from collections import Counter

import pdfplumber
from sqlalchemy.orm import Session

from backend.agent_logic.departments import policy_keywords_for
from backend.core.config import POLICY_ANOMALY_KEYWORDS, POLICY_EXCERPT_MAX_CHARS, POLICY_MIN_TEXT_CHARS_PER_PAGE


class PolicyDocumentError(Exception):
    """Raised for an upload that can't be usefully converted -- not a
    real/readable PDF, or one with no meaningful extractable text (a
    scanned/image-only document -- no OCR support, see
    docs/known_limitations.md)."""


_PAGE_NUMBER_LINE = re.compile(r"^\s*(page\s+)?\d{1,4}(\s+of\s+\d{1,4})?\s*$", re.IGNORECASE)

# Numbered/titled heading conventions this document TYPE actually uses in
# practice (formal bylaws/policy documents), favored over font-size
# heuristics -- more reliable for this specific kind of document and much
# simpler to reason about.
_HEADING_PATTERNS = [
    re.compile(r"^(article|section|chapter)\s+[\divxlcdm]+\b", re.IGNORECASE),
    re.compile(r"^\d+(\.\d+)*[.)]\s+\S"),
]


def _looks_like_heading(line: str) -> bool:
    stripped = line.strip()
    if not stripped or len(stripped) > 100:
        return False
    for pattern in _HEADING_PATTERNS:
        if pattern.match(stripped):
            return True
    # ALL-CAPS short standalone line -- the other common formal-document
    # section-title convention. Requires at least one letter (so a lone
    # page-number-ish line of digits/symbols doesn't qualify) and no
    # terminal sentence punctuation (so a shouted regular sentence in the
    # body text doesn't get mistaken for a heading).
    if (
        stripped.isupper()
        and 3 <= len(stripped) <= 80
        and not stripped.endswith((".", ",", ";"))
        and any(c.isalpha() for c in stripped)
    ):
        return True
    return False


def convert_pdf_to_markdown(pdf_bytes: bytes) -> str:
    """Extracts text page by page, strips running header/footer noise
    (any line repeated across a large fraction of pages) and bare page-
    number lines, then marks detected heading lines as Markdown `##`
    section breaks. Not full-fidelity Markdown -- the goal is clean prose
    with reliable section boundaries for select_relevant_excerpt below to
    split on, not a publication-quality document."""
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            pages_text = [(page.extract_text() or "") for page in pdf.pages]
    except Exception as e:
        raise PolicyDocumentError(f"Could not read this file as a PDF: {e}") from e

    if not pages_text:
        raise PolicyDocumentError("This PDF has no pages.")

    total_chars = sum(len(t) for t in pages_text)
    if total_chars < POLICY_MIN_TEXT_CHARS_PER_PAGE * len(pages_text):
        raise PolicyDocumentError(
            "Very little text could be extracted from this PDF -- it may be a scanned "
            "image rather than a text-based document. Scanned/image PDFs aren't "
            "supported; re-upload a text-based PDF (e.g. exported directly from a word "
            "processor)."
        )

    pages_lines = [[ln.strip() for ln in text.split("\n")] for text in pages_text]

    # A line is running header/footer noise (company name repeated on
    # every page, "Confidential", etc.) if it's BOTH repeated across a
    # large fraction of pages AND sits at the very top or bottom of the
    # page -- position matters as much as repetition. Frequency alone
    # would also catch a genuinely repeated BODY sentence (a bylaws
    # document restating the same clause verbatim in two different
    # sections, or citing itself) as if it were boilerplate, silently
    # deleting real content -- confirmed directly: a repeated body
    # paragraph landing on 2+ pages of a short test document was wrongly
    # stripped entirely before this position check was added. A real
    # header/footer, unlike a real body paragraph, is reliably confined
    # to a fixed handful of lines at the page edges.
    _EDGE_LINES = 2
    edge_line_page_counts = Counter()
    for lines in pages_lines:
        non_empty = [ln for ln in lines if ln]
        edge_candidates = set(non_empty[:_EDGE_LINES]) | set(non_empty[-_EDGE_LINES:])
        for ln in edge_candidates:
            edge_line_page_counts[ln] += 1
    repeated_threshold = max(2, int(len(pages_text) * 0.4))
    boilerplate = {ln for ln, count in edge_line_page_counts.items() if count >= repeated_threshold}

    out_lines = []
    for lines in pages_lines:
        for ln in lines:
            if not ln or ln in boilerplate or _PAGE_NUMBER_LINE.match(ln):
                continue
            out_lines.append(f"\n## {ln}\n" if _looks_like_heading(ln) else ln)

    markdown = re.sub(r"\n{3,}", "\n\n", "\n".join(out_lines)).strip()
    if not markdown:
        raise PolicyDocumentError("Nothing usable was left after cleaning this PDF's text.")
    return markdown


def split_into_sections(markdown: str) -> list[tuple[str, str]]:
    """[(heading, body_text), ...]. Content before the first detected
    heading (if any) is kept under the label "General" so it's still
    eligible for keyword matching rather than silently dropped -- some
    bylaws documents lead with unheaded preamble/definitions text that
    can itself be the most relevant section for a given trigger."""
    parts = re.split(r"^## (.+)$", markdown, flags=re.MULTILINE)
    sections: list[tuple[str, str]] = []
    if parts[0].strip():
        sections.append(("General", parts[0].strip()))
    for i in range(1, len(parts), 2):
        heading = parts[i].strip()
        body = parts[i + 1].strip() if i + 1 < len(parts) else ""
        if body:
            sections.append((heading, body))
    return sections


def _keywords_for(db: Session, company_id: int, anomalies: list[dict], department: str | None) -> set[str]:
    keywords: set[str] = set()
    for a in anomalies:
        keywords.update(POLICY_ANOMALY_KEYWORDS.get(a.get("type"), []))
    if department:
        # agent_logic/departments.py's policy_keywords_for -- a per-company
        # admin-managed Department row (was a fixed core/config.py dict
        # lookup, POLICY_DEPARTMENT_KEYWORDS, keyed on the department name
        # lowercased; that dict now only serves as seed data, and the new
        # lookup already matches on the exact stored name -- see that
        # module's own docstring for the graceful "nothing configured"
        # degradation this relies on).
        keywords.update(policy_keywords_for(db, company_id, department))
    return keywords


def select_relevant_excerpt(db: Session, company_id: int, markdown: str, anomalies: list[dict], department: str | None) -> str | None:
    """Returns the highest-scoring section(s) by simple keyword-occurrence
    count, concatenated up to POLICY_EXCERPT_MAX_CHARS -- or None if
    nothing scores at all. Returning None deliberately (rather than a
    generic/first-section fallback) when nothing matches: injecting an
    irrelevant section into the prompt is worse than injecting nothing,
    and "no policy context was available" should stay distinguishable
    from "policy context was available and actually cited".

    db/company_id: only ever used to resolve `department`'s own optional
    policy_keywords via agent_logic/departments.py -- this function is
    still otherwise a pure, no-side-effect read over `markdown`."""
    keywords = _keywords_for(db, company_id, anomalies, department)
    if not keywords:
        return None

    # Multi-word keywords match with a space OR a hyphen between words --
    # "after hours"/"after-hours", "off hours"/"off-hours" are both real,
    # common variants of the same phrase in ordinary prose, and only
    # matching the literal space would miss the hyphenated form entirely
    # (confirmed directly: a real bylaws document using "after-hours"
    # didn't match the "after hours" keyword until this was added).
    keyword_patterns = [r"\b" + re.escape(kw).replace(r"\ ", r"[\s-]+") + r"\b" for kw in keywords]

    sections = split_into_sections(markdown)
    scored = []
    for heading, body in sections:
        text = f"{heading}\n{body}"
        score = sum(len(re.findall(pat, text, flags=re.IGNORECASE)) for pat in keyword_patterns)
        if score > 0:
            scored.append((score, heading, body))

    if not scored:
        return None

    scored.sort(key=lambda x: x[0], reverse=True)

    excerpt_parts = []
    total_len = 0
    for score, heading, body in scored:
        piece = f"### {heading}\n{body}"
        if total_len + len(piece) > POLICY_EXCERPT_MAX_CHARS:
            if total_len == 0:
                # Even the single highest-scoring section alone exceeds
                # the budget -- include a truncated version rather than
                # nothing, clearly marked as truncated so the model (and
                # anyone reading context_snapshot later) knows it's partial.
                excerpt_parts.append(piece[:POLICY_EXCERPT_MAX_CHARS] + "\n... [truncated]")
            break
        excerpt_parts.append(piece)
        total_len += len(piece)

    return "\n\n".join(excerpt_parts)
