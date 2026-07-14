from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import os
from datetime import datetime

from src.models import RequestModel
from src.detector import run_detection_engine
from src.ai_explainer import generate_security_report

app = FastAPI(
    title="AI Request Scanner API",
    description="An API to scan HTTP requests for vulnerabilities and generate AI security reports.",
    version="1.0.0"
)

@app.post("/scan")
async def scan_request(request: RequestModel):
    try:
        analysis_result = run_detection_engine(request)
        
        # Await the async gemini generation to avoid blocking the server
        report = await generate_security_report(analysis_result)
        
        # Save the analysis result inside the 'fastApi result' directory with a timestamp
        os.makedirs("fastApi-result", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fastApi-result/analysis_{timestamp}.json"
        
        # Save both raw JSON and the AI Markdown report
        with open(filename, "w") as f:
            f.write(analysis_result.model_dump_json(indent=2))
        with open(filename.replace(".json", ".md"), "w") as f:
            f.write(report)
        
        response_data = {
            "analysis_json": analysis_result.model_dump(),
            "security_report": report
        }
        
        # Return HTTP 403 Forbidden if risk is HIGH or CRITICAL
        if analysis_result.metadata.risk_level in ["HIGH", "CRITICAL"]:
            return JSONResponse(
                status_code=403, 
                content=response_data
            )
            
        return response_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection Engine Error: {str(e)}")
