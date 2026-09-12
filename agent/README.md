# Windows Service & Process Monitoring Agent

A Python-based Windows security monitoring tool that monitors processes and Windows services to identify suspicious or unauthorized activity.

## Features

- Real-time Process Monitoring
- Parent-Child Process Relationship Monitoring
- Suspicious Process Detection
- Whitelist and Blacklist Checking
- Windows Service Audit
- Suspicious Service Path Detection
- Severity Classification
- Security Report Generation

## Technologies Used

- Python
- psutil
- Windows Services
- VS Code

## Project Structure

Windows-Monitoring-Agent/
│
├── agent/
│   ├── main.py
│   ├── process_monitor.py
│   ├── process_tree.py
│   ├── suspicious_process.py
│   ├── service_audit.py
│   └── report_generator.py
│
├── config/
│   ├── whitelist.txt
│   └── blacklist.txt
│
├── reports/
│
├── requirements.txt
└── README.md

## Installation

Install the required Python library:

```bash
pip install -r requirements.txt