# AGENTS.md - Project Context & Agent Instructions

## 📌 Project Overview
This project is an automated security testing and patching workflow developed for the **AI-Augmented Software Engineering (ASSE)** course (A.Y. 2025/2026).
The goal is to implement a closed-loop DevSecOps prototype using DVWA (Damn Vulnerable Web Application) hosted inside a Docker container.

### 🎯 Core Focus
* **Target Vulnerability:** Strictly **SQL Injection (SQLi)** for the core baseline. Other OWASP Top 10 flaws are strictly optional extensions.
* **Operating Mode:** Single-student project execution (Iterative sequential workflow / MVP).

---

## 🗺️ 4-Phase Workflow Architecture
When operating within this repository, you must strictly align your sub-tasks with these four explicit phases:

1.  **Vulnerability Discovery:** Analyze the application context/endpoints to generate potential exploit payloads.
2.  **Vulnerability Confirmation:** Execute payloads against the live DVWA instance and verify success by parsing HTTP responses/logs.
3.  **Patch Generation:** Analyze the vulnerable source code file alongside the successful exploit data. **The LLM outputs the full corrected source file**, which is written to disk; a unified diff is computed locally via `difflib` and persisted to `patch_report.diff` (overwritten on every patch attempt, deleted at the start of every run) purely for reporting/logging.
4.  **Patch Validation:** Lint the patched file (`php -l`) and run the dual-verification testing suite.

---

## 🧪 Evaluation & Success Criteria
A patch is considered successful **only** if it satisfies two conditions during Phase 4:
1.  **Security Test:** The exact offensive payload that previously triggered the exploit must now be successfully blocked.
2.  **Functional Regression Test:** Standard, legitimate user traffic/actions (e.g., normal logins, valid database queries) must still work perfectly. The core business logic must remain intact.

### 📊 Key Metrics to Track
You must log and report the following metrics during experimental runs:
* **Exploit Blocking Rate:** % of attacks successfully mitigated.
* **Preservation of Business Logic:** % of legitimate functional tests passing post-patch.
* **Patch Applicability:** % of full-file patches written to disk successfully (non-empty, non-identical to the original).
* **Syntax & Runtime Errors:** Compilation or PHP linting (`php -l`) failures.
* **LLM Iterations:** Number of refinement loops needed to fix a single flaw.

---

## 🛠️ Codebase & Environment Rules
* **Target Environment:** Dockerized DVWA (`https://github.com/digininja/DVWA/`).
* **Automation Code:** Python scripts handling the pipeline orchestration.
* **State Reset:** The database must be automatically reset/restored to a clean state before validation loops to ensure reproducible experiments.
* **Output Requirements:** The Blue Team LLM returns the full patched source file, which is written directly to disk; a unified diff is computed locally with `difflib` afterwards and saved to `patch_report.diff` for reporting/audit purposes only (not for application). The file is overwritten on each patch attempt and cleared at the start of every run (`node_init`), so it never accumulates across runs.

---

## 🤖 Agent Personality & Operational Constraints
* Be concise, technical, and objective.
* Do not over-engineer the pipeline architecture (prioritize a clean sequential script over an overly complex multi-agent framework unless explicitly asked).
* Focus heavily on measuring and avoiding application regression (breaking legitimate functions).