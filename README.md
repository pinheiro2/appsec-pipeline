# 🛡️ Go AppSec Pipeline: From Vulnerable to Secure

[![CI/CD Security Pipeline](https://github.com/pinheiro2/appsec-pipeline/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/pinheiro2/appsec-pipeline/actions)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)

## 📌 Project Overview
This repository demonstrates a practical implementation of a Secure Software Development Life Cycle (SDLC). It features a Go-based REST API that was intentionally engineered with classic OWASP Top 10 vulnerabilities. 

The core objective of this project is to showcase automated vulnerability detection and documented remediation through a custom-built DevSecOps pipeline, ensuring that vulnerable code never reaches production.

## ⚙️ Architecture & Tech Stack
*   **Application:** Go (Golang), standard `net/http` library, SQLite.
*   **CI/CD Pipeline:** GitHub Actions.
*   **Static Application Security Testing (SAST):** [Semgrep](https://semgrep.dev/) - Configured to scan source code for insecure patterns and hardcoded secrets on every Pull Request.
*   **Dynamic Application Security Testing (DAST):** [OWASP ZAP](https://www.zaproxy.org/) (Baseline Scan) - Configured to dynamically scan the running API container for runtime vulnerabilities.

## 🚨 Vulnerability & Remediation Log

The following table documents the vulnerabilities initially introduced, how the automated pipeline caught them, and the secure coding practices applied to resolve them.

| OWASP Category | Vulnerability Description | Detection Tool | Remediation Strategy Applied |
| :--- | :--- | :--- | :--- |
| **A03:2021-Injection** | SQL Injection in the `/users` endpoint via concatenated user input. | Semgrep (SAST) | Replaced raw SQL concatenation with parameterized queries (`db.QueryRow`). |
| **A07:2021-Identification & Auth Failures** | Hardcoded API keys present in the database connection file. | Semgrep (SAST) | Abstracted secrets to `.env` variables and implemented AWS/local Secrets Manager logic. |
| **A01:2021-Broken Access Control** | Standard users could access `/admin/transactions` via direct object reference (IDOR). | OWASP ZAP (DAST) | Implemented Role-Based Access Control (RBAC) middleware to validate JWT claims before serving the route. |

## 🔄 The CI/CD Workflow
The GitHub Actions pipeline is defined in `.github/workflows/security.yml` and executes the following steps on push to the `main` branch or upon PR creation:
1.  **Build & Unit Test:** Verifies basic application integrity.
2.  **SAST Scan:** Semgrep analyzes the `.go` files against standard security rulesets. The build fails if high-severity issues are detected.
3.  **Application Launch:** The API is containerized and spun up locally in the GitHub runner.
4.  **DAST Scan:** OWASP ZAP runs a baseline HTTP spider scan against the active endpoints.
5.  **Teardown:** The container is destroyed and artifact reports are generated.

## 🚀 How to Run Locally

### Prerequisites
*   Go 1.21+
*   Docker (for running ZAP locally)

### Running the API
```bash
# Clone the repository
git clone [https://github.com/yourusername/your-repo-name.git](https://github.com/yourusername/your-repo-name.git)
cd your-repo-name

# Install dependencies
go mod tidy

# Run the server
go run main.go
# The API will be available at http://localhost:8080
