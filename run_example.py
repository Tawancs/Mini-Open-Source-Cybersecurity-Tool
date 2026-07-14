import json
import os
import sys
from src.models import RequestModel
from src.detector.engine import run_detection_engine
from src.ai_explainer.gemini_client import generate_security_report
from dotenv import load_dotenv

import asyncio

def main():
    load_dotenv()

    # Change example file here    
    example_file = "examples/path_traversal_request.json"
    if len(sys.argv) > 1:
        example_file = sys.argv[1]
        
    print(f"[*] Running AI Request Scanner on: {example_file}")
    
    try:
        with open(example_file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[-] Error: File {example_file} not found.")
        return
        
    request = RequestModel(**data)
    
    # Phase 1: Detection
    print("[*] Running Phase 1: Detection Engine...")
    analysis = run_detection_engine(request)
    
    # Phase 2: AI Explainer
    print("[*] Running Phase 2: AI Explanation Engine...")
    report = None
    if analysis.metadata.risk_level in ["HIGH", "CRITICAL"]:
        report = asyncio.run(generate_security_report(analysis))
    else:
        print(f"[*] Skipping AI report for {analysis.metadata.risk_level} risk. Action: {analysis.metadata.action}")
    
    # Determine output directory based on example file path and risk level
    rel_path = os.path.relpath(os.path.dirname(example_file), "examples")
    if rel_path == "." or rel_path.startswith(".."):
        out_dir = os.path.join("result", analysis.metadata.risk_level)
    else:
        out_dir = os.path.join("result", rel_path, analysis.metadata.risk_level)
        
    os.makedirs(out_dir, exist_ok=True)
    
    # Extract the base name (e.g., malicious -> malicious_analysis.json)
    base_name = os.path.splitext(os.path.basename(example_file))[0]
    analysis_path = os.path.join(out_dir, f"{base_name}_analysis.json")
    
    with open(analysis_path, "w") as f:
        f.write(analysis.model_dump_json(indent=2))
        
    print(f"[+] Success! Results saved to:")
    print(f"    - {analysis_path}")
    
    if report:
        report_path = os.path.join(out_dir, f"{base_name}_report.md")
        with open(report_path, "w") as f:
            f.write(report)
        print(f"    - {report_path}")

if __name__ == "__main__":
    main()
