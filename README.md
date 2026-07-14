# Mini-Open-Source-Cybersecurity-Tool (AI Request Scanner)

**A lightweight, open-source cybersecurity tool designed to simulate the detection of common web vulnerabilities in HTTP requests and automatically generate human-readable security reports.**

---

## 🎯 The Security Problem It Solves

Security analysts and developers often have to manually sift through raw HTTP logs or network captures to identify basic web attacks. Once an attack is found, they must spend additional time translating those technical findings into a readable summary for management or clients. 

AI Request Scanner bridges this gap by automatically parsing the raw request, detecting malicious patterns (like SQLi or XSS) using a rule-based engine, and then utilizing Google's Gemini AI to instantly write a professional, easy-to-understand executive security report.

## 👥 Who Should Use It

- **Security Learners & Students:** To understand how malicious payloads look in HTTP traffic and learn how to report them.
- **Junior SOC Analysts:** To quickly generate preliminary triage reports for suspicious web requests.
- **Developers:** To validate if their input validation correctly blocks specific malicious formats.

## ⚙️ What It Does (and Does Not Do)

**What it DOES:**
- Parses structured JSON representations of HTTP requests.
- Scans for 4 specific attack types: SQL Injection, Cross-Site Scripting (XSS), Path Traversal, and OS Command Injection.
- Calculates a basic risk and confidence score based on the extracted payloads.
- Generates a markdown-formatted security report using the Gemini API.

**What it DOES NOT do:**
- It is **not** an active scanner (it does not attack or probe external systems).
- It is **not** a proxy or a firewall (it does not block traffic).
- It does **not** detect advanced or obfuscated payloads outside of its specific regex rules.

---

## 🚀 Installation

Clone the repository and run the following commands to set up the environment:

```bash
# 1. Clone the repository
git clone https://github.com/Tawancs/Mini-Open-Source-Cybersecurity-Tool.git
cd Mini-Open-Source-Cybersecurity-Tool

# 2. Set up a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install the dependencies
pip install -r requirements.txt

# 4. Set up your environment variables
cp .env.example .env
```
*Note: You must edit the `.env` file and insert your `GEMINI_API_KEY` for the AI Explanation feature to work.*

---

## ⚡ Quick Start

The fastest way to test the tool is using the included `run_example.py` script against the provided examples.

```bash
# Make sure your virtual environment is active
source venv/bin/activate

# Run the scanner against an example sql injection request
python3 run_example.py examples/sql_injection/malicious.json
```

---

## 💡 Example Input and Output

**Input (`examples/sql_injection/malicious.json`):**
```json
{
  "method": "GET",
  "url": "/login",
  "params": {
    "username": "admin' OR '1'='1"
  },
  "headers": {
    "User-Agent": "Mozilla/5.0"
  },
  "body": ""
}
```

**Output Terminal:**
```text
[*] Running AI Request Scanner on: examples/sql_injection/malicious.json
[*] Running Phase 1: Detection Engine...
[*] Running Phase 2: AI Explanation Engine...
[+] Success! Results saved to:
    - result/sql_injection/malicious_analysis.json
    - result/sql_injection/malicious_report.md
```

**Output Report (`result/sql_injection/malicious_report.md`):**
*(The AI generates a full markdown report including an Executive Summary, Attack Type, Why it was detected, Potential Impact, Severity, Recommended Mitigations, and Analyst Notes).*

---

## 🛠️ Main Options & Configuration

- **`GEMINI_API_KEY`**: Required in the `.env` file to generate the final reports.
- **`GEMINI_MODEL`**: (Optional) In `/src/ai_explainer/gemini_client.py` file, you can specify the exact model to use (defaults to `gemini-3.1-flash-lite`).
- **FastAPI Server**: You can also run the tool as a REST API backend instead of a CLI tool:
  ```bash
  uvicorn src.main:app --reload
  ```
  Then visit `http://localhost:8000/docs` to interact with it via the browser.

---

## ⚠️ Known Limitations

- **Methods Coverage (Limited Attack Types):** It is designed to scan for 4 specific attack types: SQL Injection, Cross-Site Scripting (XSS), Path Traversal, and OS Command Injection. It does not detect other types of vulnerabilities (e.g., SSRF, XXE).
- **AI Hallucinations:** While the system prompt strictly instructs the AI to only use the provided JSON, LLMs can occasionally generate inaccurate mitigation advice or hallucinate attack details.
- **Not a Perfect Tool (Heuristic & Signature Limitations):** While the detection engine uses robust, risk-tiered scoring and obfuscation normalizers (rather than simple universal pattern matching), it ultimately still relies on Regex signatures loaded from JSON configurations. It can therefore still be evaded by novel or highly complex obfuscated payloads (false negatives).
- **Scale (Single-Threaded Async):** The FastAPI server leverages asynchronous endpoints (`async def`), allowing it to handle multiple incoming HTTP network requests concurrently without blocking while waiting for AI API responses. However, because Python's core processing is limited to a single thread, the CPU-bound detection engine cannot scale to enterprise levels (e.g., thousands of requests per second) out-of-the-box without deploying multiple workers.
---

## 🛡️ Safety and Ethical-Use Note

This tool is entirely **defensive and analytical**. It does not perform any active network scanning, exploitation, or data collection. All processing happens locally (except for the API call to Google Gemini to format the final report). 

Users should only feed sample data or traffic from systems they own or are authorized to monitor into this tool. Do not upload sensitive, confidential, or Personally Identifiable Information (PII) into the JSON requests, as that data will be sent to the Gemini API for summarization.

---

## 📜 License

This project is open-source and available under the **MIT License**. See the [LICENSE](LICENSE) file for more information.