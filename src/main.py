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
        report = None
        if analysis_result.metadata.risk_level in ["HIGH", "CRITICAL"]:
            report = await generate_security_report(analysis_result)
        
        # Save the analysis result inside the 'fast-api-result' directory separated by risk level
        risk_level = analysis_result.metadata.risk_level
        save_dir = os.path.join("fastapi-result", risk_level)
        os.makedirs(save_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(save_dir, f"analysis_{timestamp}.json")
        
        # Save raw JSON
        with open(filename, "w") as f:
            f.write(analysis_result.model_dump_json(indent=2))
            
        # Save AI Markdown report only if generated
        if report:
            with open(filename.replace(".json", ".md"), "w") as f:
                f.write(report)
        
        response_data = {
            "analysis_json": analysis_result.model_dump(),
            "security_report": report if report else "No AI report generated for LOW/MEDIUM risk."
        }
        
        # Return HTTP 403 Forbidden if risk is CRITICAL
        if analysis_result.metadata.risk_level == "CRITICAL":
            return JSONResponse(
                status_code=403, 
                content=response_data
            )
            
        return response_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection Engine Error: {str(e)}")
