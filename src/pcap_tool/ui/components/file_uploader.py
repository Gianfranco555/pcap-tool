from __future__ import annotations

import streamlit as st

MAX_SIZE = 5 * 1024 * 1024 * 1024  # 5GB


def file_uploader(label: str = "Upload a PCAP or PCAP-ng file (≤ 5 GB)", key: str = "pcap_uploader"):
    """Return an uploaded file object if within size limits."""
    uploaded = st.file_uploader(label, type=["pcap", "pcapng"], key=key)
    if uploaded and uploaded.size > MAX_SIZE:
        st.error("File exceeds 5 GB limit.")
        return None
    return uploaded
