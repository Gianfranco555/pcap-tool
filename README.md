graph TD
    subgraph Local Mac
        User[(Engineer)]
        WebUI[Web UI (React)]
        APIGW[FastAPI API]
        LocalDisk[(Local Disk - ./data)]
        SQLite[(SQLite DB)]
        Celery[Celery (eager mode)]
        Logs[(JSON log files)]
    end
    User -->|HTTPS| WebUI
    WebUI --> APIGW
    APIGW --> LocalDisk
    APIGW --> SQLite
    APIGW --> Celery
    Celery --> LocalDisk
    Celery --> SQLite
    Celery --> Logs
    %% future prod pieces, disabled in dev
    APIGW -.-> OIDC[(OIDC SSO)]
    APIGW -.-> SNOW[(ServiceNow)]
    Celery -.-> Splunk[(Splunk HEC)]
    Celery -.-> S3[(S3/MinIO)]
    Celery -.-> Broker[(RabbitMQ)]
    SQLite -.-> Postgres[(PostgreSQL)]
Solid lines show the pieces that exist in this repository. Dashed lines in the
diagram are features planned for later (API server, Celery workers, etc.).

Current repository layout:

pcap-tool/
├─ CHANGELOG.md
├─ README.md
├─ pyproject.toml
├─ requirements.txt
├─ src/
│  ├─ app.py              # Streamlit demo UI
│  ├─ heuristics/
│  │   ├─ engine.py
│  │   └─ rules.yaml
│  └─ pcap_tool/
│      ├─ __main__.py     # CLI entry point
│      ├─ parser.py
│      └─ pdf_report.py
├─ tests/                 # pytest suites
├─ pytest.ini
└─ .flake8
Key notes

* The command-line parser works today and outputs DuckDB or Arrow files.
* `src/app.py` offers a minimal Streamlit demo.
* The FastAPI API, Celery tasks and external adapters are still TODO.

## Prerequisites

* Python (e.g., 3.12 - as per Action Plan)
* pip (for Python package management)
* tshark (will be installed by the setup script if using one, or needs manual install)
* [Node.js & npm/yarn - if frontend setup is included]
* [Docker - if docker-compose.dev.yml is a primary setup method]

## Local Development Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd pcap-tool
    ```
2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```
3.  **Install system dependencies (if not using a comprehensive setup script like the one we discussed):**
    *(Mention tshark or point to the setup script)*
4.  **Install Python dependencies:**
    ```bash
    pip install --upgrade pip
    pip install -r requirements.txt
    ```
5.  *(No environment variables are required for the basic CLI parser)*

## Running the Application

### Command-line
```bash
python -m pcap_tool parse example.pcap --output duckdb://flows.db
```

### Optional Streamlit UI
```bash
streamlit run src/app.py
```

The FastAPI API, React frontend and Celery workers are planned for a later release.

## Running Tests

```bash
pytest
```

### Multiprocessing Parser

`iter_parsed_frames` uses multiple processes by default to speed up large PCAP files. Pass `workers=0` to disable multiprocessing; otherwise up to four processes are used.

### Command-Line Parsing

Parse a capture directly to DuckDB for ad-hoc SQL:

```bash
pcap-tool parse big.pcap --output duckdb://big.db
duckdb big.db "SELECT tunnel_type, COUNT(*) FROM flows GROUP BY 1;"
```
