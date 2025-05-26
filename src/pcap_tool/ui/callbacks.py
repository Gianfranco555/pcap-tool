from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pandas as pd

from .session_state import AppState
from pcap_tool.pipeline_app import run_analysis


def analyze_pcap(uploaded_file: st.runtime.uploaded_file_manager.UploadedFile, rules_path: Path, state: AppState, on_progress=None) -> None:
    state.analysis_ran = True
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.getvalue())
            temp_file_path = tmp.name
        metrics_output, tagged_flow_df, text_summary, pdf_bytes = run_analysis(Path(temp_file_path), rules_path, on_progress=on_progress)
        state.metrics_output = metrics_output
        state.tagged_flow_df = tagged_flow_df
        state.text_summary = text_summary
        state.pdf_bytes = pdf_bytes
    except Exception:
        state.metrics_output = None
        state.tagged_flow_df = pd.DataFrame()
        state.text_summary = ""
        state.pdf_bytes = b""
        raise
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
