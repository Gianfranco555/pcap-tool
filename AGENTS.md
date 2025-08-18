# AGENTS.md
This file provides guidance for AI agents interacting with the pcap-tool codebase.

**Project Overview**
pcap-tool is a Python-based tool for parsing, analyzing, and generating reports from PCAP files. It features a modular architecture with components for parsing, enrichment, analysis, and reporting. The tool can be used as a command-line application or through a Streamlit-based web UI.

**Key Directories**:

- src/pcap_tool/: The main source code for the project.
		- parser/: Contains the logic for parsing PCAP files, with support for pyshark and pcapkit.
		- heuristics/: Includes the heuristic engine and rules for analyzing network flows.
		- analysis/: Houses modules for performance analysis, error summarization, and security auditing.
		- reporting/: Contains components for generating PDF and Excel reports.
		- ui/: The Streamlit-based web interface for the tool.
- tests/: Contains the pytest test suite for the project.
- docs/: Includes project documentation, such as architecture notes and performance guidelines.
  

**Core Technologies and Libraries**:

- Parsing: pyshark, pypcapkit, scapy

- Data Manipulation: pandas, numpy

- Web UI: streamlit, altair, plotly

- Reporting: reportlab

- AI Summarization: openai


**Architectural Principles**:

**Modularity**: The codebase is organized into distinct modules for parsing, analysis, and reporting, which allows for easy extension and maintenance.

**Fallback Mechanisms**: The parser is designed to fall back to pcapkit if pyshark is not available, ensuring greater flexibility.

**Vectorization**: The heuristic engine leverages vectorized operations in pandas for efficient analysis of network flows.

**Extensibility**: The pipeline architecture allows for the addition of new processors, analyzers, and reporters to extend the tool's functionality.
 
**test**: |
  # Run the full pytest suite quietly (dots only)
  pytest -q
  
**lint**: |
  flake8 src/ tests/
