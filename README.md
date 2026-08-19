# 🛡️ Go AppSec Pipeline: From Vulnerable to Secure

[![CI/CD Security Pipeline](https://github.com/pinheiro2/appsec-pipeline/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/pinheiro2/appsec-pipeline/actions)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev/)

## 📌 Project Overview
This repository demonstrates a practical implementation of a Secure Software Development Life Cycle (SDLC) and Test-Driven Security. It features a Go-based REST API intentionally engineered with classic OWASP Top 10 vulnerabilities. 

The core objective of this portfolio project is to showcase automated vulnerability detection, security tool tuning, and documented remediation through a custom-built DevSecOps pipeline, ensuring that vulnerable code never reaches production.

## ⚙️ Architecture & Tech Stack
*   **Application:** Go (Golang), standard `net/http` library, pure-Go `modernc.org/sqlite`.
*   **CI/CD Pipeline:** GitHub Actions (with cryptographically pinned Action hashes).
*   **Static Application Security Testing (SAST):** [Semgrep](https://semgrep.dev/) - Configured to run OSS rulesets (Default, Go, OWASP) and natively upload SARIF results to the GitHub Advanced Security tab.
*   **Dynamic Application Security Testing (DAST):** [OWASP ZAP API Scan](https://www.zaproxy.org/) - Configured to ingest an OpenAPI (`swagger`) specification to actively attack and fuzz hidden API endpoints, automatically generating GitHub Issues for findings.

## 🗺️ Project Roadmap & Completed Tasks
- [x] Build initial vulnerable Go REST API and SQLite database.
- [x] Implement GitHub Actions CI/CD pipeline using `workflow_dispatch`.
- [x] Integrate Semgrep SAST and configure clean pipeline exits with SARIF uploads.
- [x] Create `openapi.yaml` specification to map hidden API attack surface.
- [x] Integrate OWASP ZAP DAST (Active API Scan) to dynamically fuzz the running application.
- [x] **Remediate:** SQL Injection (SQLi) using Prepared Statements.
- [x] **Remediate:** Hardcoded Secrets using fail-closed Environment Variables and GitHub Secrets.
- [x] **Remediate:** Broken Object Level Authorization (BOLA/IDOR) via strict caller-ID verification.
- [x] Verify complete remediation with 0 High/Medium severity alerts in final DAST report.

## 🚨 Vulnerability & Remediation Log

| OWASP Category | Vulnerability Description | Detection Tool | Remediation Strategy Applied |
| :--- | :--- | :--- | :--- |
| **A03:2021-Injection** | SQL Injection in `/api/users/search` via concatenated `fmt.Sprintf` input. | Semgrep (SAST) & ZAP (DAST) | Replaced raw SQL concatenation with parameterized queries (`db.Query`). |
| **A07:2021-Identification & Auth Failures** | Hardcoded JWT signing key present in `main.go`. | Semgrep (SAST) | Abstracted secret to `os.Getenv`, implemented fail-closed startup logic, and securely passed via GitHub Actions Secrets. |
| **A01:2021-Broken Access Control** | BOLA/IDOR on `/api/user/profile`. Users could access any profile by enumerating the `?id=` parameter. | Manual / ZAP (DAST) | Implemented Object-Level Authorization checks comparing the simulated `X-User-Id` claim against the requested resource ID. |

## 🔄 The CI/CD Workflow
The GitHub Actions pipeline is defined in `.github/workflows/security-pipeline.yml` and executes the following steps:
1.  **SAST Scan:** Semgrep analyzes the `.go` files against standard security rulesets and uploads a `.sarif` file directly to the repository's Security tab.
2.  **Application Build & Launch:** The Go API is compiled and spun up as a background process locally in the Ubuntu GitHub runner, injecting CI/CD vault secrets into the environment.
3.  **DAST Scan:** OWASP ZAP reads `.github/config_files/openapi.yaml` and launches an active API scan against the live local endpoints.
4.  **Reporting:** ZAP automatically opens a GitHub Issue containing the dynamic fuzzing results and artifact reports.

## 🚀 How to Run Locally

### Prerequisites
*   Go 1.22+

### Running the API
```bash
# 1. Clone the repository
git clone [https://github.com/yourusername/appsec-pipeline.git](https://github.com/yourusername/appsec-pipeline.git)
cd appsec-pipeline

# 2. Create a local environment file with a dummy secret
echo "JWT_SECRET=my-local-dev-secret-key" > .env

# 3. Export the secret and run the server
export $(cat .env | xargs) && go run main.go

# The API will be available at http://localhost:8080