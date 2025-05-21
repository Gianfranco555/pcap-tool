"""PDF reporting utilities."""

from __future__ import annotations

from io import BytesIO
from typing import Any, Dict, Optional

import re
from statistics import mean

import pandas as pd

from .chart_generator import protocol_pie_chart, top_ports_bar_chart
from .exceptions import ReportGenerationError
from .metrics_builder import select_top_flows


def _sparkline_chart(values: list[int]) -> bytes:
    """Return a tiny bar chart PNG for sparkline values."""
    if not values:
        return b""
    try:  # pragma: no cover - optional dependency
        import matplotlib.pyplot as plt
    except Exception:  # pragma: no cover - matplotlib may not be installed
        return b""

    fig, ax = plt.subplots(figsize=(1.4, 0.25), dpi=100)
    ax.bar(range(len(values)), values, color="#4B8BBE")
    ax.axis("off")
    fig.patch.set_alpha(0.0)
    buf = BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", pad_inches=0, transparent=True)
    plt.close(fig)
    return buf.getvalue()


def _build_elements(
    metrics_json: Dict[str, Any],
    flows_df: Optional[pd.DataFrame],
    styles,
    summary_text: str | None = None,
) -> list:
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib import colors

    elements: list = []

    capture_info = metrics_json.get("capture_info", {})
    title_text = "PCAP Analysis Report"
    if capture_info.get("filename"):
        title_text += f" - {capture_info['filename']}"

    elements.append(Paragraph(title_text, styles["Title"]))
    elements.append(Spacer(1, 12))

    if capture_info:
        elements.append(Paragraph("Capture Summary", styles["Heading2"]))
        filename = capture_info.get("filename")
        if filename is not None:
            elements.append(Paragraph(f"Filename: {filename}", styles["Normal"]))
        size = capture_info.get("file_size")
        if size is not None:
            elements.append(Paragraph(f"File size: {size}", styles["Normal"]))
        packets = capture_info.get("total_packets")
        if packets is not None:
            elements.append(Paragraph(f"Total packets: {packets}", styles["Normal"]))
        duration = capture_info.get("capture_duration")
        if duration is not None:
            elements.append(Paragraph(f"Capture duration: {duration}", styles["Normal"]))

        other_keys = {
            k: v
            for k, v in capture_info.items()
            if k
            not in {"filename", "file_size", "total_packets", "capture_duration"}
        }
        for k, v in other_keys.items():
            elements.append(Paragraph(f"{k}: {v}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    if summary_text:
        elements.append(Paragraph("AI-Generated Summary", styles["Heading2"]))
        for line in summary_text.splitlines():
            if line.strip():
                elements.append(Paragraph(line.strip(), styles["Normal"]))
        elements.append(Spacer(1, 12))

    proto_counts = metrics_json.get("protocols", {})
    if proto_counts:
        elements.append(Paragraph("Protocol Distribution", styles["Heading2"]))
        chart_bytes = protocol_pie_chart(proto_counts)
        if chart_bytes:
            elements.append(Image(BytesIO(chart_bytes), width=200, height=200))
        else:
            for proto, count in proto_counts.items():
                elements.append(Paragraph(f"{proto}: {count}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    port_counts = metrics_json.get("top_ports", {})
    if port_counts:
        elements.append(Paragraph("Top Ports", styles["Heading2"]))
        chart_bytes = top_ports_bar_chart(port_counts)
        if chart_bytes:
            elements.append(Image(BytesIO(chart_bytes), width=300, height=200))
        else:
            for p, c in port_counts.items():
                elements.append(Paragraph(f"{p}: {c}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    if flows_df is not None and not flows_df.empty:
        flows_df = select_top_flows(flows_df)
        elements.append(Paragraph("Top Flows", styles["Heading2"]))

        preferred_cols = [
            "src_ip",
            "dest_ip",
            "src_port",
            "dest_port",
            "protocol",
            "l7_protocol_guess",
            "bytes_total",
            "pkts_total",
        ]
        display_cols = [c for c in preferred_cols if c in flows_df.columns]
        if not display_cols:
            display_cols = list(flows_df.columns[:8])

        table_df = flows_df[display_cols].head(20).fillna("")
        spark_re = re.compile(r"sparkline_.*")

        header_map = {
            "src_ip": "Source IP",
            "dest_ip": "Destination IP",
            "src_port": "Src Port",
            "dest_port": "Dst Port",
            "l7_protocol_guess": "L7 Proto",
            "bytes_total": "Bytes",
            "pkts_total": "Packets",
        }
        headers = [header_map.get(c, c) for c in display_cols]

        data = [headers]
        for _, row in table_df.iterrows():
            row_vals = []
            for col in display_cols:
                val = row[col]
                if spark_re.match(col):
                    if isinstance(val, str):
                        parts = [p for p in val.split(',') if p]
                        numbers = [int(p) for p in parts if p.isdigit()]
                    else:
                        try:
                            numbers = [int(v) for v in val]
                        except Exception:
                            numbers = []
                    img_bytes = _sparkline_chart(numbers)
                    if img_bytes:
                        row_vals.append(Image(BytesIO(img_bytes), width=100, height=16))
                    else:
                        if numbers:
                            row_vals.append(
                                f"Trend: {min(numbers)} -> {max(numbers)}, Avg: {mean(numbers):.1f}"
                            )
                        else:
                            row_vals.append("")
                else:
                    row_vals.append(str(val))
            data.append(row_vals)
        table = Table(data, repeatRows=1, hAlign="LEFT")
        style_cmds = [
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ]

        numeric_idx = [
            i
            for i, c in enumerate(display_cols)
            if pd.api.types.is_numeric_dtype(table_df[c]) and not spark_re.match(c)
        ]
        for idx in numeric_idx:
            style_cmds.append(("ALIGN", (idx, 1), (idx, -1), "RIGHT"))

        table.setStyle(TableStyle(style_cmds))
        elements.append(table)
        elements.append(Spacer(1, 12))

    perf = metrics_json.get("performance_metrics", {})
    if perf:
        elements.append(Paragraph("Performance Metrics", styles["Heading2"]))
        for k, v in perf.items():
            elements.append(Paragraph(f"{k}: {v}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    errors = metrics_json.get("error_summary", {})
    if errors:
        elements.append(Paragraph("Error Summary", styles["Heading2"]))
        for k, v in errors.items():
            elements.append(Paragraph(f"{k}: {v}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    sec = metrics_json.get("security_findings", {})
    if sec:
        elements.append(Paragraph("Security Findings", styles["Heading2"]))
        for k, v in sec.items():
            elements.append(Paragraph(f"{k}: {v}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    timeline = metrics_json.get("timeline_data", [])
    spikes = [t for t in timeline if t.get("spike")]
    if spikes:
        elements.append(Paragraph("Timeline Spikes", styles["Heading2"]))
        for spike in spikes:
            ts = spike.get("timestamp")
            bytes_ = spike.get("bytes")
            elements.append(
                Paragraph(f"Spike at {ts}: {bytes_} bytes", styles["Normal"])
            )
        elements.append(Spacer(1, 12))

    return elements


def generate_pdf_report(
    metrics_json: Dict[str, Any],
    top_flows_df: Optional[pd.DataFrame] = None,
    summary_text: str | None = None,
) -> bytes:
    """Generate a PDF report from ``metrics_json``.

    Parameters
    ----------
    metrics_json:
        The metrics dictionary produced by :class:`MetricsBuilder`.
    top_flows_df:
        Optional ``DataFrame`` of flows to include as a table. If not
        provided, ``metrics_json['top_talkers_by_bytes']`` will be used.
    summary_text:
        Optional plain-English summary text to include in the report.

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

    flows_df = top_flows_df
    if flows_df is None:
        records = (
            metrics_json.get("top_flows")
            or metrics_json.get("top_talkers_by_bytes")
            or []
        )
        if records:
            flows_df = pd.DataFrame(records)

    try:
        elements = _build_elements(metrics_json, flows_df, styles, summary_text)
        doc.build(elements)
    except Exception as exc:
        raise ReportGenerationError(str(exc)) from exc

    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


if __name__ == "__main__":
    metrics = {
        "capture_info": {"filename": "example.pcap"},
        "protocols": {"tcp": 5, "udp": 3},
        "top_ports": {"tcp_80": 5, "udp_53": 3},
        "top_talkers_by_bytes": [
            {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "bytes_total": 1234}
        ],
        "performance_metrics": {"median_rtt_ms": 5, "retrans_pct": 0.1},
        "error_summary": {},
        "security_findings": {},
        "timeline_data": [],
    }
    report_bytes = generate_pdf_report(metrics)
    with open("example_report.pdf", "wb") as fh:
        fh.write(report_bytes)
