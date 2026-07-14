# AI Request Scanner - User Manual

This manual provides detailed instructions on how to set up, operate, and troubleshoot the AI Request Scanner.

---

## 1. Requirements and Supported Environment

- **OS:** Windows, macOS, or Linux.
- **Python:** Python 3.8 or higher.
- **Dependencies:** `fastapi`, `uvicorn`, `google-genai`, `pydantic`, `python-dotenv`.
- **API Key:** A valid Google Gemini API Key (free tier works fine).

---

## 2. Installation Instructions

1. **Clone or Download the Code:** Open your terminal and navigate to your preferred directory, then clone the repository.
   ```bash
   git clone https://github.com/Tawancs/Mini-Open-Source-Cybersecurity-Tool.git
   cd Mini-Open-Source-Cybersecurity-Tool
   ```
2. **Create a Virtual Environment:** This keeps the dependencies isolated from your main system.
   ```bash
   python3 -m venv venv
   ```
3. **Activate the Virtual Environment:**
   - **Mac/Linux:** `source venv/bin/activate`
   - **Windows (PowerShell):** `.\venv\Scripts\activate`
4. **Install Dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```
5. **Configure API Key:**
   Copy `.env.example` to a new file named `.env` and paste your Gemini API key inside.
   ```bash
   cp .env.example .env
   # Open .env and set GEMINI_API_KEY=your_key_here
   ```

---

## 3. Step-by-Step Usage Guide

The AI Request Scanner can be used in two modes: **CLI Script Mode** and **REST API Mode**.

### Mode A: CLI Script Mode (Recommended for testing)

This mode runs a single JSON file through the pipeline and saves the results to a folder.

**Command:**
```bash
python3 run_example.py [path_to_json_file]
```
- **Example:** `python3 run_example.py examples/xss/malicious.json`
- **What it does:** Reads the JSON file, runs the detection engine, queries Gemini, and creates a `result/` directory containing the JSON analysis and Markdown report.

### Mode B: REST API Mode

This mode starts a local web server, allowing you to send multiple requests on the fly.

**Command:**
```bash
uvicorn src.main:app --reload
```
- **What it does:** Starts the server on `http://127.0.0.1:8000`.
- **How to test:** 
  1. Open your browser to `http://127.0.0.1:8000/docs`.
  2. Click on the `POST /scan` box.
  3. Click "Try it out".
  4. Paste your JSON request into the Request body box and click "Execute".

---

## 4. Explanation of Input Format

The system expects a standard JSON payload representing an HTTP request. 

**Format:**
```json
{
  "method": "GET", 
  "url": "/api/data",
  "params": {
    "key1": "value1"
  },
  "headers": {
    "User-Agent": "curl/7.68.0"
  },
  "body": "string content"
}
```
*Note: `params`, `headers`, and `body` are optional, but providing them gives the scanner more context to find malicious patterns.*

---

## 5. Explanation of Output Fields

When the scan finishes, it produces two outputs:

1. **Analysis JSON:** The raw, technical output from Phase 1.
   - `request`: A mirror of what you submitted.
   - `features`: The exact malicious strings (like `SELECT` or `<script>`) the engine extracted.
   - `detections`: A list indicating the `type` of attack found (e.g., SQL Injection) and a `confidence` score (0.0 to 1.0).
   - `metadata`: Contains the overall `risk_level` (LOW, MEDIUM, HIGH, CRITICAL) and the recommended `action` to take.
2. **Markdown Report:** The AI-generated output from Phase 2.
   - `Executive Summary`: High-level overview of the findings.
   - `Recommended Mitigations`: Actionable steps developers can take to fix the vulnerability.

---

## 6. Complete Worked Example

**Step 1:** Create an input file named `test.json` containing an obvious attack:
```json
{
  "method": "GET",
  "url": "/view",
  "params": {"file": "../../../../etc/passwd"}
}
```

**Step 2:** Run the CLI script:
```bash
python3 run_example.py test.json
```

**Step 3:** View the output on your terminal:
```text
[*] Running AI Request Scanner on: test.json
[*] Running Phase 1: Detection Engine...
[*] Running Phase 2: AI Explanation Engine...
[+] Success! Results saved to:
    - result/CRITICAL/test_analysis.json
    - result/CRITICAL/test_report.md
```

**Step 4:** Open the generated files to see the results.

**`result/CRITICAL/test_analysis.json` (Phase 1 output):**
```json
{
  "request": {
    "method": "GET",
    "url": "/view",
    "params": {
      "file": "../../../../etc/passwd"
    }
  },
  "features": {
    "detected_keywords": ["../", "/etc/passwd"],
    "encoding": "None",
    "suspicious_patterns": ["../", "/etc/passwd"],
    "detailed_detections": [
      {
        "pattern": "../",
        "description": "Relative directory traversal",
        "location": "params.file"
      },
      {
        "pattern": "/etc/passwd",
        "description": "Sensitive file access",
        "location": "params.file"
      }
    ]
  },
  "detections": [
    {
      "type": "Path Traversal",
      "confidence": 1.0,
      "reasoning": "Detected 2 Path Traversal patterns: ../ (in params.file), /etc/passwd (in params.file)"
    }
  ],
  "metadata": {
    "risk_level": "CRITICAL",
    "action": "Block the request (HTTP 403 Forbidden).",
    "timestamp": "2026-07-14T07:58:18.116758+00:00"
  }
}
```

**`result/CRITICAL/test_report.md` (Phase 2 AI output):**
```markdown
**Request Arrived At:** `2026-07-14T07:58:18`

### Security Incident Report

#### 1. Executive Summary
A critical security incident was identified on 2026-07-14 at 07:58:18 UTC. An external request was flagged for attempting to perform a path traversal attack to access sensitive system files.

#### 2. Attack Type
*   **Name:** Path Traversal
*   **Confidence:** 1.0

#### 3. Why it was detected
*   **Evidence:** The HTTP GET request contained malicious file path sequences in the `file` parameter.
*   **Location:** `params.file` (Relative path traversal and sensitive file access)
*   **Patterns:** `../`, `/etc/passwd`
*   **Reasoning:** The system detected a combination of directory traversal sequences (`../`) and a request for a sensitive system file (`/etc/passwd`).

#### 4. Potential Impact
Successful exploitation would allow an unauthorized actor to read arbitrary files from the server's filesystem, specifically targeting sensitive system configuration files (e.g., `/etc/passwd`), potentially leading to full system compromise or information disclosure.

#### 5. Severity
**CRITICAL**

#### 6. Recommended Mitigations
*   **Input Validation:** Implement strict allow-listing for the `file` parameter to ensure only permitted filenames are accessible.
*   **Path Sanitization:** Use built-in framework functions to resolve and validate file paths, ensuring the requested file resides within the designated, safe directory.
*   **Access Controls:** Ensure the application process runs with the least privilege required, restricting read access to system-critical files like `/etc/passwd`.
```

---

## 7. Troubleshooting

- **`ModuleNotFoundError: No module named 'src'`**
  - *Cause:* You tried to run `python src/main.py`. 
  - *Fix:* You must run the API using `uvicorn src.main:app --reload`.
- **`Error: GEMINI_API_KEY environment variable is not set.`**
  - *Cause:* The `.env` file is missing or the key is blank. 
  - *Fix:* Ensure you renamed `.env.example` to `.env` and inserted your key. Restart your server/script afterwards.
- **`404 NOT_FOUND ... model is no longer available`**
  - *Cause:* Google deprecated the AI model version.
  - *Fix:* Open your `.env` file and add `GEMINI_MODEL=gemini-3.1-flash-lite` to override it with a stable model.


