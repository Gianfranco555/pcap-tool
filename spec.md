# PCAP-Analysis Tool – Specification (v1.0)

> **Change Log**  
> *14 May 2025 – v1.0 created (initial import)*  
> *14 May 2025 – heading levels normalised; change-log & architecture link added; Open Questions stub*

## 1. Purpose
Provide an internal web-based tool that ingests PCAP/PCAP-ng files, prioritising Zscaler-generated captures in the Minimum Viable Product (MVP) and progressively expanding to vendor-agnostic packet captures. The tool quickly pinpoints why sessions were blocked, allowed, or degraded, thereby cutting mean-time-to-resolution (MTTR) for network and security teams. :contentReference[oaicite:0]{index=0}:contentReference[oaicite:1]{index=1}

## 2. Scope & Phased Vision
| Phase | Capture Types Supported | Key Outcomes |
|-------|-------------------------|--------------|
| **MVP (Phase 1)** | Zscaler-generated PCAP/PCAP-ng | Upload, automated parsing, root-cause analysis, exportable report |
| **Phase 2** | Generic PCAP/PCAP-ng (any vendor) | Modular parsers, protocol coverage > 80 % of common enterprise traffic |
| **Phase 3** | Extensibility SDK | Plugin system for bespoke protocol decoders & AI-powered insights |

## 3. Stakeholders
**Primary:** Network engineers, security analysts, support engineers  
**Secondary:** Incident response, service desk, IT leadership  
**Enablers:** DevOps, InfoSec, Compliance :contentReference[oaicite:2]{index=2}:contentReference[oaicite:3]{index=3}

## 4. User Stories (MVP-focused)
| ID | As a … | I want to … | So that … |
|----|---------|-------------|-----------|
| US-1 | Network engineer | upload a Zscaler PCAP-ng file via browser | I can diagnose a customer outage without CLI tools |
| US-2 | Security analyst | see “blocked vs allowed vs degraded” sessions with reasons | I triage incidents faster |
| US-3 | Support engineer | download a concise PDF/CSV of findings | I can attach evidence to a ticket |
| US-4 | Engineer | filter results by user, IP, URL, or timeframe | I isolate a single transaction quickly |
| US-5 | DevOps admin | integrate the tool with SSO/OIDC & RBAC | access is secure and auditable |
| US-6 | Product owner | view KPIs (avg processing time, accuracy) on a dashboard | I measure product value and plan improvements | :contentReference[oaicite:4]{index=4}:contentReference[oaicite:5]{index=5}

## 5. Functional Requirements
### 5.1 Capture Ingestion
* **R-F-01** Browser drag-and-drop & REST API upload ≤ 5 GB/file  
* **R-F-02** Store raw files in object storage (MinIO S3-compatible)  
* **R-F-03** Validate file type (PCAP or PCAP-ng) and checksum

### 5.2 Parsing & Session Reconstruction
* **R-F-04** Decode Ethernet → IP → TCP/UDP/ICMP protocols  
* **R-F-05** For Zscaler captures, map flows to ZIA/ZPA metadata  
* **R-F-06** Identify application-layer protocols (HTTP(S), DNS, TLS)  
* **R-F-07** Reassemble sessions; compute latency, retransmissions, handshake success

### 5.3 Root-Cause Analysis
* **R-F-08** Classify each session into Allowed, Blocked, Degraded, or Unknown  
* **R-F-09** Surface causal attributes (policy hit, SSL error, DNS failure, congestion)  
* **R-F-10** Leverage optional OpenAI API to generate plain-language summaries

### 5.4 Interface & Reporting
* **R-F-11** Responsive web UI (React + Tailwind) with sortable table & timeline view  
* **R-F-12** Advanced filters: user/IP, URL/FQDN, protocol, time range, outcome  
* **R-F-13** Export findings to PDF, CSV, JSON  
* **R-F-14** Show processing progress and allow background notification on completion

### 5.5 Security & Access
* **R-F-15** Authenticate via corporate SSO (OIDC)  
* **R-F-16** Role-based access: Viewer, Analyst, Admin  
* **R-F-17** Encrypt data at rest (AES-256) and in transit (TLS 1.3)

### 5.6 Administration & DevOps
* **R-F-18** Containerised microservices (Docker/K8s) with Helm charts  
* **R-F-19** Expose health metrics (`/metrics`) for Prometheus/Grafana  
* **R-F-20** Provide REST endpoints documented via OpenAPI 3 :contentReference[oaicite:6]{index=6}:contentReference[oaicite:7]{index=7}

## 6. Non-Functional Requirements
| Category | Requirement |
|----------|-------------|
| **Performance** | Process 1 GB PCAP within ≤ 120 s on a 4-core worker; UI FCP < 2 s on 10 Mbps link |
| **Scalability** | Horizontal worker pool; support ≥ 20 concurrent jobs without degradation |
| **Accuracy** | Root-cause classification F-score ≥ 0.90 on labelled validation set |
| **Usability** | 90 % of first-time users complete US-1 in ≤ 5 minutes without docs |
| **Availability** | 99.5 % monthly uptime; graceful job resume after node failure |
| **Maintainability** | PEP 8 codebase & ≥ 80 % unit-test coverage; automated CI/CD |
| **Security** | ISO 27001-aligned; least-privilege IAM; secrets in Vault |
| **Compliance** | No PII persisted beyond 30 days; GDPR & internal retention policy |
| **Internationalisation** | Unicode support; locale-aware date/time (initially en-US) | :contentReference[oaicite:8]{index=8}:contentReference[oaicite:9]{index=9}

## 7. Key Performance Indicators (KPIs)
| KPI | Target (MVP) | Measurement |
|-----|--------------|-------------|
| Processing Time / GB | ≤ 120 s | Backend timer logs |
| Classification Accuracy | ≥ 90 % F-score | Weekly model validation |
| MTTR Reduction | ≥ 40 % vs manual Wireshark | Engineer survey & ticket stats |
| User Adoption | ≥ 50 active users within 3 months | SSO login metrics |
| Export Usage | ≥ 70 % of analysed jobs generate a report | Audit logs |
| System Uptime | ≥ 99.5 % | Prometheus SLA dashboard | :contentReference[oaicite:10]{index=10}:contentReference[oaicite:11]{index=11}

## 8. Out-of-Scope (MVP)
* Real-time packet capture or live traffic sniffing  
* Editing, anonymising, or re-writing PCAPs  
* Deep malware sandboxing or threat-intel correlation  
* Mobile-native app (web-only)  
* Decrypting encrypted payloads without provided keys  
* On-prem installation (cloud-hosted only for MVP) :contentReference[oaicite:12]{index=12}:contentReference[oaicite:13]{index=13}

## 9. Dependencies & Assumptions
* Corporate SSO is OIDC-compliant and reachable from the deployment VPC  
* Object storage (MinIO or S3) is provisioned with appropriate IAM roles  
* OpenAI API keys are available for optional AI summaries; safe fallback path exists  
* Labelled Zscaler captures are available for model training :contentReference[oaicite:14]{index=14}:contentReference[oaicite:15]{index=15}

## 10. Risks & Mitigations
| Risk | Impact | Mitigation |
|------|--------|-----------|
| Inaccurate parsing of non-Zscaler PCAPs | Delays Phase 2 | Modular parser architecture; prototype with Scapy/PyShark |
| Large upload sizes saturate bandwidth | Poor UX | Resumable uploads & client-side compression checks |
| Model drift reduces accuracy | Mis-classification | Scheduled re-training; KPI alerts |
| Sensitive data exposure | Compliance breach | AES-256 encryption; signed URLs; retention purge jobs | :contentReference[oaicite:16]{index=16}:contentReference[oaicite:17]{index=17}

## 11. Acceptance Criteria (MVP)
* Upload, parse, classify, and report on a 500 MB Zscaler PCAP-ng within SLA  
* At least five user stories (US-1 → US-5) satisfied in staging demo  
* All Functional & Non-Functional targets met or exceeded  
* InfoSec signs off the security & compliance checklist :contentReference[oaicite:18]{index=18}:contentReference[oaicite:19]{index=19}

## 12. High-Level Architecture
![Architecture diagram](docs/architecture.png)

*(Mermaid `.mmd` source lives in `docs/architecture.mmd`; regenerate PNG via `make diagram`.)*

## 13. Open Questions
1. Should the MVP support IPv6 flow reconstruction?  
2. Exact AI prompt/response token limits for on-prem customers?  
3. Minimum retention period for audit logs—7 days or 30?  

## 14. Change Management
The product manager owns this specification; changes follow the engineering RFC process with version control and stakeholder sign-off. :contentReference[oaicite:20]{index=20}:contentReference[oaicite:21]{index=21}
