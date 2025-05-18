
import streamlit as st

# TODO: implement
from pcap_tool.parser import parse_pcap
from heuristics.engine import HeuristicEngine

    HeuristicEngine,  # TODO: implement
)


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

analysis_attempted = False

if uploaded_file and st.button("Parse & Analyze"):
    with st.spinner("Parsing…"):
        analysis_attempted = True
        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng") as tmp:
                tmp.write(uploaded_file.getvalue())
                temp_file_path = tmp.name
            parsed_df = parse_pcap(temp_file_path)
            rules_path = Path(__file__).resolve().parent / "heuristics" / "rules.yaml"
            engine = HeuristicEngine(str(rules_path))
            df = engine.tag_flows(parsed_df)
        except Exception as exc:
            st.error(f"Error parsing file: {exc}")
            df = None
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

if df is not None and not df.empty:
    output_area.dataframe(df)
else:
    if not uploaded_file:
        output_area.write("Upload a PCAP file to begin analysis.")
    elif not analysis_attempted:
        output_area.write("Click 'Parse & Analyze' to see results.")
    else:
        output_area.write(
            "No analysis results to display. Check for errors above or try a different file."
        )

csv_data = b""
if df is not None and not df.empty:
    csv_data = df.to_csv(index=False).encode("utf-8")

st.download_button(
    "Download CSV Report",
    csv_data,
    file_name="report.csv",
    disabled=df is None or df.empty,
)
st.download_button(
    "Download PDF Report",
    b"",
    file_name="report.pdf",
    disabled=True,
)

if uploaded_file and st.button("Parse & Analyze"):
    with st.spinner("Parsing…"):
        try:
            # df = parse_pcap(uploaded_file)
            # tagged_df = HeuristicEngine("rules.yaml").tag(df)
            # df = tagged_df
            pass
        except Exception as exc:
            st.error(f"Error parsing file: {exc}")
            df = None

if df is not None:
    output_area.dataframe(df)
else:
    output_area.write("Analysis results will appear here.")

st.download_button("Download CSV Report", b"", file_name="report.csv")
st.download_button("Download PDF Report", b"", file_name="report.pdf")


if __name__ == "__main__":
    print("Run this GUI with:  streamlit run src/app.py")
