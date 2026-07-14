# Test Report: AI Request Scanner

**Test Date:** July 14, 2026\
**Environment:** macOS / Python 3.13.3 (Virtual Environment)\
**Tool Version:** v1.1.0

---

## 1. Test Cases

The engine was evaluated against a suite of 49 unit tests spanning four major vulnerability categories. The following test cases demonstrate the core capabilities of the tool across the supported attack types and edge cases.

| Test | Command / Input | Expected | Actual | Status |
|---|---|---|---|---|
| T1 Unit Tests | `pytest test/ -v` | All 49 core engine unit tests pass | 49 tests passed successfully | Pass |
| T2 SQLi Detection | `python run_example.py examples/sql_injection/malicious.json` | Detects SQL Injection with HIGH/CRITICAL risk | Found SQL Injection with 0.9 confidence | Pass |
| T3 XSS Detection | `python run_example.py examples/xss/malicious.json` | Detects XSS with HIGH/CRITICAL risk | Found Cross-Site Scripting with high confidence | Pass |
| T4 Path Traversal | `python run_example.py examples/path_traversal/malicious.json` | Detects Path Traversal with HIGH/CRITICAL risk | Found Path Traversal with high confidence | Pass |
| T5 Invalid File Path | `python run_example.py missing.json` | Clear error message | Shows `FileNotFoundError` | Pass |

---

## 2. Evaluation Harness Results

The tool was evaluated against a large-scale dataset (`WAF_DETECTION_DATASET.jsonl`), containing 650 valid malicious requests categorized into four vulnerability types. This dataset was sourced from the [WAF_DETECTION_DATASET on Hugging Face](https://huggingface.co/datasets/darkknight25/WAF_DETECTION_DATASET/blob/main/WAF_DETECTION_DATASET.jsonl).

The detection engine was evaluated across all requests with a risk threshold set to MEDIUM/HIGH/CRITICAL (confidence $\ge$ 0.4). The following confusion matrix highlights the engine's performance across the four attack types:

| Category | True Positive (TP) | False Positive (FP) | True Negative (TN) | False Negative (FN) | Precision | Recall |
|---|---|---|---|---|---|---|
| **SQL Injection** | 119 | 0 | 514 | 11 | 1.00 | 0.92 |
| **Cross-Site Scripting** | 252 | 5 | 384 | 3 | 0.98 | 0.99 |
| **Path Traversal** | 86 | 66 | 448 | 44 | 0.57 | 0.66 |
| **Command Injection** | 129 | 40 | 475 | 0 | 0.76 | 1.00 |

**Conclusion:** 
The tool demonstrates strong detection capabilities across all four vulnerability classes, with particularly outstanding performance in SQL Injection and Cross-Site Scripting, achieving nearly perfect precision and recall. However, Command Injection and Path Traversal exhibit higher False Positive rates. 

For **Command Injection**, this is primarily due to isolated shell operators (e.g., `|`, `&`) or single instances of `uname -a`, which are flagged under the `MEDIUM` risk threshold even when not combined in a threatening manner. 

For **Path Traversal**, the engine struggles to detect heavily obfuscated payloads that bypass the standard `../` pattern matching (e.g. Triple slashes).

---

## 3. Architecture & Heuristic Updates

During extensive testing against tricky benign payloads (e.g., `select=shoes`, `curl is a command-line tool`, `<b>Hello World</b>`), the following critical architectural improvements were implemented:

- **Removal of `sqlparse`:** The heavy SQL parsing library was removed entirely. It was notoriously prone to flagging isolated English words as SQL keywords, causing massive False Positives. 
- **Risk-Tiered Signatures:** The detection engine now natively supports `LOW`, `MEDIUM`, and `HIGH` risk signatures directly from the JSON configurations. 
  - `LOW` signatures (e.g., `INSERT INTO`, `DELETE FROM`) score `0.1`.
  - `MEDIUM` signatures (e.g., `--` SQL comment) score `0.3`.
  - `HIGH` signatures (e.g., `UNION SELECT`, `' OR '1'='1`) score `0.9`.
- **Path Traversal Tuning:** The score for a single `directory traversal` was adjusted to `0.6` and `null byte` to `0.5`, requiring a combination to trigger a `HIGH` (0.7) or `CRITICAL` (0.9) block.
- **Command Injection Tuning:** The `dangerous command` score was reduced to `0.4` and `shell operator` adjusted to `0.3` to ensure that combinations are properly bucketed into `MEDIUM` and `HIGH` tiers without overly punishing single occurrences.
- **Duplicate Scoring Cap:** The engine now tracks extracted feature descriptions to ensure that repeating the same low-risk character (e.g. multiple `<` tags in an HTML payload) does not falsely compound into a `HIGH` risk score.

---

## 4. Known Bugs and Limitations

The tool's detection capabilities are currently limited to four specific vulnerability types (SQLi, XSS, Path Traversal, and OS Command Injection) and rely on risk-tiered regular expressions, meaning highly obfuscated payloads may bypass detection (False Negatives). Additionally, because the tool utilizes Google Gemini to generate the final human-readable reports, the AI may occasionally hallucinate or provide inaccurate mitigation advice, requiring users to manually verify the final report against the raw JSON analysis.
