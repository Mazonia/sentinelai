# SentinelAI - AI-Powered Security Scanner

SentinelAI is a state-of-the-art, AI-powered web application security scanner designed for comprehensive vulnerability assessment and penetration testing automation.

## Features

- **Comprehensive Scanning**: SQL Injection, XSS, Authentication flaws, API vulnerabilities, Security misconfigurations
- **AI-Powered Analysis**: Intelligent false positive reduction, risk scoring, automated remediation advice
- **Modern Architecture**: FastAPI backend, React frontend, PostgreSQL database, Redis task queue
- **Automation**: CI/CD integration, scheduled scans, webhook notifications
- **Scalability**: Distributed scanning with Celery workers

## Quick Start

### Using Docker Compose

1. Clone the repository
2. Copy environment file:
   ```bash
   cp .env.example .env
   # Edit .env with your settings