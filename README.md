# 🛡️ AI-SOC-Analyst

An AI-powered Security Operations Center (SOC) Analyst platform that ingests real Sysmon EVTX logs, performs threat detection and hunting, correlates alerts, enriches indicators with threat intelligence, maps findings to MITRE ATT&CK, and generates automated incident reports through an interactive Streamlit dashboard.

---

## 🚀 Features

### 🔍 Real Sysmon EVTX Ingestion

* Parse real Windows Sysmon EVTX logs
* Extract process creation and security events
* Analyze endpoint activity

### 🚨 Detection Engine

* Encoded PowerShell Detection
* Malware Execution Detection
* Multiple Failed Login Detection
* Malicious IP Communication Detection
* Data Exfiltration Detection

### 🎯 Threat Hunting

* Suspicious PowerShell Activity
* LOLBin Detection
* Suspicious Parent-Child Process Detection

### 🔗 Alert Correlation

Correlates multiple detections into higher-confidence incidents.

Example:

* Encoded PowerShell Execution
* Suspicious Parent Child Process

➡️ Multi-Stage Attack Detected

### 🧠 MITRE ATT&CK Mapping

Automatically maps alerts to MITRE ATT&CK tactics and techniques.

Examples:

| Alert                        | Tactic              | Technique |
| ---------------------------- | ------------------- | --------- |
| Encoded PowerShell Execution | Execution           | T1059.001 |
| Multiple Failed Logins       | Credential Access   | T1110     |
| Malicious IP Communication   | Command and Control | T1071     |
| Data Exfiltration Attempt    | Exfiltration        | T1041     |

### 🌍 Threat Intelligence Enrichment

Enriches indicators with:

* GeoIP Information
* AbuseIPDB Reputation
* VirusTotal Intelligence
* WHOIS Data

### 🏢 Asset Criticality Analysis

Classifies assets by business importance:

* Critical
* High
* Medium
* Low

### 🤖 AI Alert Triage

Automatically evaluates alerts and generates:

* Executive Summary
* Threat Assessment
* Confidence Score
* Verdict
* Recommended Actions

### 📄 Automated Incident Reporting

Generates analyst-ready incident reports including:

* Alert Details
* MITRE ATT&CK Mapping
* Threat Intelligence
* Asset Criticality
* AI Assessment
* Recommended Actions

### 📊 Streamlit SOC Dashboard

Interactive dashboard featuring:

* SOC Metrics
* Alert Severity Distribution
* Risk Score Analysis
* MITRE ATT&CK Summary
* Threat Intelligence
* AI Triage Results
* Incident Reports

---

## 🏗️ Project Architecture

```text
AI-SOC-Analyst
│
├── alerts/
├── ai/
├── detection/
├── enrichment/
├── parsers/
├── raw_logs/
├── reports/
├── output/
│
├── dashboard.py
├── run_evtx_detection.py
├── test_hunting.py
├── test_correlation.py
└── requirements.txt
```

---

## 🛠️ Tech Stack

### Languages

* Python

### Security Tools

* Sysmon
* MITRE ATT&CK

### Frameworks

* Streamlit

### Data Processing

* EVTX Parsing
* JSON

### Threat Intelligence

* GeoIP
* AbuseIPDB
* VirusTotal
* WHOIS

---

## 📸 Dashboard Capabilities

### SOC Metrics

* Total Alerts
* Critical Alerts
* High Severity Alerts
* Average Risk Score

### Threat Analysis

* MITRE ATT&CK Mapping
* Threat Intelligence Enrichment
* AI Triage

### Incident Response

* Automated Incident Reports
* Correlated Attack Detection
* Analyst Recommendations

---

## 🔬 Example Detection Workflow

```text
Sysmon EVTX Logs
        ↓
EVTX Parser
        ↓
Detection Engine
        ↓
Threat Hunting Rules
        ↓
Alert Correlation
        ↓
Threat Intelligence
        ↓
MITRE ATT&CK Mapping
        ↓
AI Triage
        ↓
Incident Report
        ↓
SOC Dashboard
```

---

## ▶️ Installation

Clone the repository:

```bash
git clone https://github.com/chandumothukuri/AI-SOC-Analyst.git
cd AI-SOC-Analyst
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate virtual environment:

### Windows

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Run Detection Engine

```bash
python run_evtx_detection.py
```

---

## ▶️ Launch Dashboard

```bash
streamlit run dashboard.py
```

---

## 🎯 Key Skills Demonstrated

* SOC Operations
* Threat Hunting
* Detection Engineering
* Incident Response
* Threat Intelligence
* MITRE ATT&CK
* Log Analysis
* Python Automation
* Security Analytics
* Security Monitoring

---

## 🔮 Future Improvements

* Sigma Rule Support
* Splunk Integration
* Real-Time Log Streaming
* IOC Management
* Email Alerting
* Detection Coverage Dashboard
* Threat Intelligence APIs
* SIEM Integration

---

## 👨‍💻 Author

**Chandu Mothukuri**

Cybersecurity Student | SOC Analyst Aspirant | Detection Engineering Enthusiast

GitHub:
https://github.com/chandumothukuri

---

## ⭐ Version

Current Release:

**v1.0**
