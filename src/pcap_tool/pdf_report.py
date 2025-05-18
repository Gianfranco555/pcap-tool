import pandas as pd
from io import BytesIO


def generate_pdf_report(df: pd.DataFrame) -> bytes:
    """Generate a PDF report from the provided DataFrame.

    The report contains a title, a summary section and a table
    of key columns from the DataFrame. The PDF content is returned
    as ``bytes``.

    Parameters
    ----------
    df:
        Input DataFrame containing parsed PCAP flows.

    Returns
    -------
    bytes
        The generated PDF as bytes.

    Raises
    ------
    ImportError
        If the ReportLab library is not installed.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
        )
    except Exception as exc:  # pragma: no cover - dependency may be missing
        raise ImportError(
            "ReportLab is required to generate PDF reports"
        ) from exc

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("PCAP Analysis Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    # Summary
    total_records = len(df)
    elements.append(Paragraph(f"Total flows: {total_records}", styles["Normal"]))

    if "predicted_issue_category" in df.columns:
        counts = df["predicted_issue_category"].value_counts()
        for category, count in counts.items():
            elements.append(
                Paragraph(
                    f"{category}: {count}", styles["Normal"]
                )
            )
    elements.append(Spacer(1, 12))

    # Table of key columns
    preferred_cols = [
        "frame_number",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "predicted_issue_category",
        "issue_details",
    ]
    display_cols = [c for c in preferred_cols if c in df.columns]
    if not display_cols:
        display_cols = list(df.columns)

    table_df = df[display_cols].head(50).fillna("")
    data = [display_cols] + table_df.values.tolist()

    table = Table(data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    elements.append(table)

    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


if __name__ == "__main__":
    sample = pd.DataFrame(
        {
            "frame_number": [1, 2],
            "timestamp": [0.1, 0.2],
            "source_ip": ["10.0.0.1", "10.0.0.2"],
            "destination_ip": ["10.0.0.2", "10.0.0.3"],
            "protocol": ["TCP", "UDP"],
        }
    )
    report_bytes = generate_pdf_report(sample)
    with open("example_report.pdf", "wb") as fh:
        fh.write(report_bytes)
