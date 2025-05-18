"""
Phase 6 (Streamlit UI MVP)

Covered user stories US-1 & US-3

Remaining TODOs (hook parser, hook heuristic engine, export logic)
"""

import os
import tempfile
from pathlib import Path

import streamlit as st

# Assuming your project structure makes these imports valid when running from project root
# and app.py is in src/
# If pcap_tool is a directory directly under src/ (i.e., src/pcap_tool/)
# and heuristics is under pcap_tool (i.e., src/pcap_tool/heuristics/)
from pcap_tool.parser import parse_pcap
from heuristics.engine import HeuristicEngine

st.set_page_config(page_title="PCAP Analysis Tool")
st.title("PCAP Analysis Tool")

uploaded_file = st.file_uploader(
    "Upload a PCAP or PCAP-ng file (≤ 5 GB)",
    type=["pcap", "pcapng"],
)
if uploaded_file and uploaded_file.size > 5 * 1024 * 1024 * 1024:
    st.error("File exceeds 5 GB limit.")
    uploaded_file = None

output_area = st.empty()
df = None
analysis_ran = False # From Codex branch

if uploaded_file and st.button("Parse & Analyze"):
    with st.spinner("Parsing…"): # Spinner message from Codex branch
        analysis_ran = True # From Codex branch
        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".pcapng"
            ) as tmp:
                tmp.write(uploaded_file.getvalue())
                temp_file_path = tmp.name

            parsed_df = parse_pcap(temp_file_path)

            # Path to rules.yaml needs to be robust.
            # If app.py is in src/ and rules.yaml is in src/pcap_tool/heuristics/rules.yaml
            # and you run streamlit from the project root (pcap-tool/)
            rules_path = Path("src") / "pcap_tool" / "heuristics" / "rules.yaml"
            # The original Codex path might be:
            # rules_path = (
            #     Path(__file__).resolve().parent / "heuristics" / "rules.yaml"
            # )
            # This above path from Codex implies 'heuristics' is a sibling to 'app.py'
            # OR that 'app.py' is inside 'pcap_tool' and 'heuristics' is a subfolder.
            # Given your file structure from README (heuristics under pcap_tool),
            # and assuming app.py is in src/, the following adjustment is needed for rules_path:

            # Let's adjust rules_path based on app.py being in src/
            # and pcap_tool being a sub-directory of src/
            # If app.py is at src/app.py:
            # SCRIPT_DIR = Path(__file__).resolve().parent # This would be src/
            # rules_path = SCRIPT_DIR / "pcap_tool" / "heuristics" / "rules.yaml"
            # This seems more likely to work.

            # For now, I will use the most robust way assuming app.py is in src/
            # and the command 'streamlit run src/app.py' is run from the pcap-tool/ root directory.
            try:
                # Get the directory of the currently running app.py script
                app_dir = Path(__file__).resolve().parent
                # Try to construct path assuming app.py is in src/ and rules.yaml is in src/pcap_tool/heuristics
                rules_path_attempt1 = app_dir / "pcap_tool" / "heuristics" / "rules.yaml"
                # Try to construct path assuming app.py is in project_root/src (and streamlit run from project_root)
                # and rules.yaml is in project_root/src/pcap_tool/heuristics
                project_root_based_path = Path("src") / "pcap_tool" / "heuristics" / "rules.yaml"

                if rules_path_attempt1.exists():
                    rules_path = rules_path_attempt1
                elif project_root_based_path.exists():
                    rules_path = project_root_based_path
                else:
                    # Fallback or error if rules.yaml is not found
                    # This was the original line in the Codex branch for rules_path,
                    # which assumes heuristics is a sibling to app.py, or app.py is in pcap_tool
                    # For now, I'll keep the structure implied by the original Codex diff,
                    # but this path is VERY sensitive to where app.py is and where heuristics is.
                    # The original Codex path:
                    rules_path = Path(__file__).resolve().parent / "heuristics" / "rules.yaml"
                    # If this still causes "ModuleNotFoundError" for heuristics.engine later, it means
                    # this path logic or the import for HeuristicEngine needs adjustment based on
                    # your *actual confirmed* file structure for app.py and the heuristics module.
                    #
                    # Based on your earlier ModuleNotFoundError for 'src.pcap_tool.heuristics',
                    # it seems app.py is likely in 'src/' and 'pcap_tool' is a subdir of 'src'.
                    # The import `from pcap_tool.heuristics.engine import HeuristicEngine`
                    # implies that the `src` directory itself is on the python path.
                    # So, the rules path should be relative to that:
                    rules_path = Path("src/pcap_tool/heuristics/rules.yaml") # Most likely correct if running from project root
                    if not rules_path.exists(): # Failsafe for other common structure
                        rules_path = Path("pcap_tool/heuristics/rules.yaml")


            except Exception as path_ex:
                st.error(f"Could not determine path for rules.yaml: {path_ex}")
                raise # Re-raise to stop execution if path is critical

            engine = HeuristicEngine(str(rules_path))
            df = engine.tag_flows(parsed_df)
        except Exception as exc:
            st.error(f"Error during analysis: {exc}") # Corrected error message part
            df = None
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

if df is not None and not df.empty:
    output_area.dataframe(df)
else:
    if uploaded_file is None: # From Codex branch
        output_area.write("Upload a PCAP file to begin analysis.")
    elif not analysis_ran: # From Codex branch
        output_area.write("Click 'Parse & Analyze' to see results.")
    else: # From Codex branch
        output_area.write(
            "No analysis results to display. "
            "Check for errors above or try a different file."
        )

csv_data = b""
download_disabled = True # From Codex branch
if df is not None and not df.empty:
    csv_data = df.to_csv(index=False).encode("utf-8")
    download_disabled = False # From Codex branch

st.download_button(
    "Download CSV Report",
    csv_data,
    file_name="report.csv",
    disabled=download_disabled, # From Codex branch
)
st.download_button(
    "Download PDF Report",
    b"",
    file_name="report.pdf",
    disabled=True,
)

# Removed the duplicated block from phase4-tests that was just placeholders

if __name__ == "__main__":
    print("Run this GUI with:  streamlit run src/app.py")
