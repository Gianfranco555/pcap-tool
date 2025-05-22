from __future__ import annotations

"""Helper utilities for streamlit presentation elements."""


def render_status_pill(label: str, count: int, is_error: bool = True) -> str:
    """Return HTML for a colored status pill.

    Parameters
    ----------
    label:
        Descriptive label for the pill.
    count:
        Number of issues or items related to ``label``.
    is_error:
        If ``True`` a non-zero ``count`` will render a red pill with a
        cross mark. Otherwise a green pill with a check mark is used.
    """
    if count == 0:
        text = f"\u2713 No {label.lower()}" if label else "\u2713 No issues"
        color = "#28a745"
    else:
        icon = "\u2717" if is_error else "\u2713"
        color = "#dc3545" if is_error else "#28a745"
        text = f"{icon} {count} {label}"
    return f"<span class='status-pill' style='background:{color};'>{text}</span>"
