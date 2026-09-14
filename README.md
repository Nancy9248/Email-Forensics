# 🛡️ AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform
> **Smart India Hackathon (SIH) High-Impact Cybersecurity Solution**  
> *Real-Time BEC Detection, Header Origin Traceability, Geolocation Mapping, Graph Attribution & Forensic Intelligence Engine*

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.1](https://img.shields.io/badge/Framework-Flask_3.1-00F0FF.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-00FF9D.svg)](https://opensource.org/licenses/MIT)
[![SIH Ready](https://img.shields.io/badge/SIH-2026_Edition-FF007F.svg)](#-sih-problem-statement-alignment)

---

## 📌 Executive Summary & Background

Email remains the primary vector for communication across government ministries, defense organizations, enterprise ecosystems, financial institutions, and academic networks. However, traditional security mechanisms—such as spam filters, static blacklists, and signature rules—fail to intercept modern **Business Email Compromise (BEC)**, display-name spoofing, AI-generated phishing, and relay-path manipulation.

Existing security tools simply filter or drop suspicious emails but **lack forensic intelligence capabilities** to trace transmission paths, locate origin server infrastructure, correlate cross-case identities, and produce legal chain-of-custody documentation.

This platform bridges that gap by providing an end-to-end **AI-Powered Forensic Intelligence Engine** that ingests raw `.eml` files, validates authentication signatures, reconstructs SMTP relay hops, maps originating IP geolocations, detects social engineering cues via NLP/ML models, and generates court-admissible forensic PDF reports.

---

## 🎯 SIH Problem Statement Alignment

| Problem Area | Industry Challenge | Platform Solution |
| :--- | :--- | :--- |
| **Detection Limitations** | Standard spam filters miss AI-generated BEC & display-name spoofing. | **NLP & ML Threat Engine** analyzing urgency, financial diversion cues, and header anomalies. |
| **Origin Blindness** | Organizations cannot trace the physical location or infrastructure of attackers. | **Earliest Node Hop Tracing** & IP Geolocation (City, Country, ISP, VPN/TOR detection). |
| **Attribution Void** | Isolated attacks are seen as one-offs rather than coordinated campaigns. | **Graph-Based Entity Correlation** linking shared domains, IPs, and threat infrastructure into campaigns. |
| **Legal Compliance** | Lack of evidentiary standards for law enforcement & institutional reporting. | **Chain-of-Custody Audit Log** & Automated Forensic PDF Report Exporter. |

---

## 🧠 System Architecture & Workflow

```
               +-------------------------------------------------------+
               |             RAW EMAIL INGESTION (.eml File)           |
               +-------------------------------------------------------+
                                           |
                                           v
       +-----------------------------------------------------------------------+
       |                  EMAIL HEADER & PROTOCOL PARSER                       |
       |  - Extract Return-Path, Received Hops, Message-ID, Reply-To            |
       |  - Validate SPF Alignment, DKIM Signatures, DMARC Authentication      |
       +-----------------------------------------------------------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
+---------------------------------------+     +---------------------------------------+
|    ORIGIN TRACE & GEO-INTELLIGENCE    |     |      NLP & ML THREAT ENGINE           |
| - Trace earliest reliable SMTP hop    |     | - Subject & Body TF-IDF / Classifier  |
| - IP Geolocation (City, Region, ISP)  |     | - Urgency & BEC Cues (Invoice, Pay)   |
| - VPN / TOR / Proxy Infrastructure    |     | - Display-Name & Spoofing Detection   |
| - Domain WHOIS & DNS Fingerprinting   |     | - Obfuscated URL & Link Extraction    |
+---------------------------------------+     +---------------------------------------+
                    |                                             |
                    +----------------------+----------------------+
                                           |
                                           v
       +-----------------------------------------------------------------------+
       |             GRAPH CORRELATION & CAMPAIGN ATTRIBUTION                  |
       | - Cross-case IP & Domain Relationship Analysis                        |
       | - Fraud Risk Score Weighting (0 - 100)                                |
       | - Automated Campaign Clustering                                       |
       +-----------------------------------------------------------------------+
                                           |
                                           v
       +-----------------------------------------------------------------------+
       |        IIT QUANTUM CRYPTOGRAPHY DASHBOARD & FORENSIC REPORTS           |
       | - Real-Time Alert Banner & Verdict Stamp                              |
       | - Interactive Leaflet Origin Map                                      |
       | - Immutable Chain-of-Custody Audit Trail                              |
       | - Forensic PDF Report Export for Law Enforcement & SIEM Integration   |
       +-----------------------------------------------------------------------+
```

---

## 🔑 Key Modules & Technical Implementation

### 1. 🤖 Fraudulent Email Detection Engine (NLP & ML)
- **Natural Language Processing (NLP)**: Analyzes email subject lines and body text for urgency triggers, financial diversion phrases, and social engineering indicators.
- **BEC & Impersonation Classifier**: Detects executive impersonation, fraudulent invoice requests, credential harvesting links, and deceptive display-name mismatches.
- **Machine Learning Integration**: Trained Scikit-Learn TF-IDF classification models categorizing emails into `Safe`, `Suspicious`, or `Malicious` threat tiers with a calibrated 0–100 Fraud Score.

### 2. 🔬 Email Header & Protocol Analysis Module
- **Header Structure Inspection**: Deep parsing of `Return-Path`, `Received` chain, `Message-ID`, `Reply-To`, and authentication headers.
- **SPF, DKIM & DMARC Verification**: Validates whether the email traversed authorized infrastructure or manipulated relay servers.
- **Routing Anomaly Detection**: Identifies forged transmission records, relay tampering, and domain alignment failures.

### 3. 📍 Origin Traceability & Geolocation Intelligence
- **Earliest Reliable Node Extraction**: Dissects `Received:` headers backward through proxies to isolate the true originating IP address.
- **IP Geolocation Mapping**: Resolves origin coordinates (City, Region, Country, ISP) and flags anonymized networks (**VPN**, **TOR exit nodes**, **Cloud Proxy**, **Hosting Provider**).
- **Domain Fingerprinting**: Queries WHOIS data, DNS records, and registrar age to identify newly registered suspicious domains.

### 4. 🕸️ Identity Correlation & Campaign Attribution
- **Cross-Case Graph Analysis**: Links ingested emails sharing sender domains, originating IPs, or infrastructure fingerprints.
- **Automated Campaign Clustering**: Groups isolated attacks into unified threat campaigns for institutional awareness.
- **Attribution Confidence Scoring**: Computes threat actor operating environments (compromised account vs. spoofed domain vs. malicious infrastructure).

### 5. 🎨 Analyst Dashboard & IIT Quantum Cryptography Visual Engine
- **IIT Quantum Cryptography Background**: Full HTML5 Canvas 2D engine featuring cascading SHA-256 code streams, rotating optical reticles, oscillating quantum waveforms, and interactive holographic decryption lenses.
- **Real-Time Interactive Map**: Leaflet.js mapping demonstrating the estimated geographic origin of the threat.
- **Forensic PDF Export**: One-click generation of chain-of-custody PDF reports containing full evidence logs, hop timelines, and attribution rationale.

### 6. 🔒 Privacy, Legal & Evidentiary Safeguards
- **Chain-of-Custody Audit Log**: Immutable logging of all analysis events, search queries, and PDF exports for legal review.
- **Data Privacy & Masking**: Configurable PII masking for sender email addresses during investigative triage.
- **Retention Cleanup**: Automated purging of raw `.eml` uploads past organizational retention limits while preserving analytical case intelligence.

---

## 💡 Key Differentiators (Why This Solution Wins)

1. **Investigative Forensic Deep-Dive**: Unlike conventional spam filters that silently drop emails, this platform provides actionable origin intelligence for law enforcement and SIEM response units.
2. **Multi-Vector Fraud Scoring**: Fuses NLP body analytics, header relay validation, IP reputation, and domain age into a unified confidence-weighted risk score.
3. **State-of-the-Art IIT Visual Interface**: Built with an immersive Quantum Cryptography theme that wows evaluators and simplifies complex data visualization for security analysts.
4. **Law Enforcement & SIEM Ready**: Exportable PDF forensic reports designed to support institutional incident response and legal proceedings.

---

## 🛠️ Tech Stack & Dependencies

- **Core Backend**: Python 3.10+, Flask 3.1
- **Machine Learning & NLP**: Scikit-Learn, Pandas, NumPy, Joblib
- **Email Parsing & Forensics**: EML Parser, Python-WHOIS, DNSPython, PublicSuffixList
- **PDF Report Generation**: ReportLab 5.0
- **Frontend & Visuals**: HTML5 Canvas 2D, Vanilla CSS3 (Glassmorphism), JavaScript ES6+, Leaflet.js

---

## 🚀 Quick Start Guide (Local Setup)

### Prerequisites
- Python 3.10 or higher
- Git

### Installation Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Nancy9248/Email-Forensics.git
   cd Email-Forensics
   ```

2. **Set Up Virtual Environment**:
   ```bash
   # On Windows:
   python -m venv venv
   venv\Scripts\activate

   # On macOS/Linux:
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Required Packages**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the Platform**:
   ```bash
   python app/server.py
   ```

5. **Access in Browser**:
   Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🌐 Cloud Deployment (Vercel & Render Ready)

This repository is fully configured for zero-setup deployment on cloud platforms:

### Deploy on Vercel
1. Fork / Clone this repository.
2. Import the repository on [Vercel.com](https://vercel.com).
3. Vercel automatically detects `vercel.json` and deploys your serverless platform instantly!

### Deploy on Render
1. Create a Web Service on [Render.com](https://render.com).
2. Set Build Command: `pip install -r requirements.txt`
3. Set Start Command: `gunicorn --chdir app server:app`

---

## 📄 License & Attribution

This project is developed for **Smart India Hackathon (SIH)** and distributed under the **MIT License**.  
Developed with ❤️ by Team Nancy.
