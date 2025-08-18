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
Solid lines are active in the POC; dashed lines are placeholders kept in code but turned off via config.

pcap-tool/
├─ .env.example           # sample config; copy to .env for local run
├─ docker-compose.dev.yml # optional: spin up RabbitMQ/S3 later
├─ README.md
├─ pyproject.toml
├─ src/
│  ├─ api/                # FastAPI routes
│  ├─ services/           # orchestration logic
│  ├─ workers/            # Celery tasks (auto-eager in dev)
│  ├─ adapters/
│  │   ├─ snow.py         # ServiceNow client (stub in dev)
│  │   ├─ splunk.py       # Splunk HEC client (stub in dev)
│  │   └─ storage.py      # S3 vs. local-disk abstraction
│  ├─ models/             # Pydantic & ORM
│  ├─ utils/              # helpers, logging
│  └─ config.py           # Pydantic BaseSettings (DEV/PROD switch)
├─ stubs/                 # lightweight mocks for external services
│  └─ __init__.py
├─ tests/                 # pytest suites
├─ scripts/               # CLI tools (db init, demo upload)
├─ migrations/            # Alembic (SQLite→Postgres compatible)
└─ docs/                  # architecture notes, run-books
Key tweaks

stubs/ & adapters/*—production clients and dev mocks share the same interface, so swapping is just settings.env.

storage.py—writes to ./data/ in dev, S3 in prod.

config.py—single source of truth; ENV=dev sets SQLite, eager Celery, stub ServiceNow, etc.

docker-compose.dev.yml—optional; lets you add RabbitMQ or MinIO locally without changing code.

These changes keep the codebase production-ready while letting you run everything on your Mac today with uvicorn src.api.main:app --reload.

## Prerequisites

* Python (e.g., 3.12 - as per Action Plan)
* pip (for Python package management)
* tshark (will be installed by the setup script if using one, or needs manual install)
* [Node.js & npm/yarn - if frontend setup is included]
* [Docker - if docker-compose.dev.yml is a primary setup method]
* Key Python packages like `pandas`, `scapy`, `pyshark` (and the optional
  `pypcapkit` fallback).  These are managed through `requirements.txt`.

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
3.  **Install system dependencies**
    `tshark` must be installed and available in your `PATH`. For Ubuntu/Debian:
    ```bash
    sudo apt-get update && sudo apt-get install -y tshark
    ```
    On macOS with Homebrew:
    ```bash
    brew install wireshark
    ```
4.  **Install Python dependencies:**
    ```bash
    pip install --upgrade pip
    pip install -r requirements.txt
    ```
    Download the free MaxMind GeoLite2-Country database and place the
    `GeoLite2-Country.mmdb` file in a known location (e.g. `./data`) so the
    enrichment step can resolve country codes.
5.  **Set up environment variables:**
    ```bash
    cp .env.example .env
    ```
    *(Mention if any variables in .env need to be changed for a basic local run)*
6.  **Initialize the database (if applicable):**
    ```bash
    python src/scripts/initialize_db.py # Or whatever your script is
    ```

## Running the Application

* **Backend API (FastAPI):**
    ```bash
    uvicorn src.api.main:app --reload
    ```
    *(API will be available at http://localhost:8000)*
* **Frontend WebUI (React):**
    *(Add commands here, e.g., `cd path/to/frontend && npm start`)*
    *(WebUI will be available at http://localhost:3000)*
* **Celery Workers (if not using eager mode for specific testing):**
    *(Add command if needed)*

## Running Tests

Install the dependencies listed in `requirements.txt` before running the test
suite:

```bash
pip install -r requirements.txt
pytest
```
You can also run `make setup` to install everything needed for local testing.

## Optional Features

This project supports optional features that can be installed as extras. These features are only supported on Linux and macOS.

### IP Defragmentation

For IP defragmentation support, install the `defrag` extra:

```bash
pip install -e .[defrag]
```

### TCP Reassembly

For TCP reassembly support, install the `reassembly` extra:

```bash
pip install -e .[reassembly]
```

### Data Columns

Parsed DataFrames include many fields from the capture.  The `is_src_client`
column indicates whether the source of a TCP packet is the initiating client of
its flow.

### Multiprocessing Parser

`iter_parsed_frames` uses multiple processes by default to speed up large PCAP files. Pass `workers=0` to disable multiprocessing; otherwise up to four processes are used.

### Command-Line Parsing

Parse a capture directly to DuckDB for ad-hoc SQL:

```bash
pcap-tool parse big.pcap --output duckdb://big.db
duckdb big.db "SELECT tunnel_type, COUNT(*) FROM flows GROUP BY 1;"
```

## Analysis API

Analysis helpers such as `PerformanceAnalyzer`, `ErrorSummarizer` and
`SecurityAuditor` live under the `pcap_tool.analysis` namespace. The older
`pcap_tool.analyze` package remains as a deprecated alias and will be removed in
a future release.
