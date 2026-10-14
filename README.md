# 4Lizz Recon //

## Overview
Developed by **Ali Alizada** leveraging AI-driven development, this tool automates the reconnaissance phase of bug bounty hunting and penetration testing. It combines multiple active and passive intelligence sources to map out a target's attack surface and ranks discovered subdomains by risk level.

### Key Features
* **Multi-Source Enumeration:** Integrates seamlessly with passive and active tools like **Subfinder, Shodan, SecurityTrails**, and more.
* **Risk-Based Prioritization:** Automatically categorizes and sorts discovered subdomains based on their potential security risk.
* **Exportable Reports:** Download filtered and sorted results in clean formats for your next testing phase.

## Başlatma
1. Backend (Python FastAPI):
   ```bash
   python -m uvicorn backend.server:app --host 127.0.0.1 --port 8000
   ```
2. Frontend (Vite + React):
   ```bash
   npm.cmd run dev
   ```
3. Brauzerdə açın: `http://localhost:5173/`
