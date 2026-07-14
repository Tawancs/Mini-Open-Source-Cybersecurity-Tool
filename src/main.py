from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import os
from datetime import datetime

from src.models import RequestModel
from src.detector import run_detection_engine

app = FastAPI(
    title="AI Request Scanner API",
    description="An API to scan HTTP requests for vulnerabilities and generate AI security reports.",
    version="1.0.0"
)

@app.post("/scan")
async def scan_request(request: RequestModel):
    try:
        analysis_result = run_detection_engine(request)
        
        # Save the analysis result inside the 'fastApi result' directory with a timestamp
        os.makedirs("fastApi result", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fastApi result/analysis_{timestamp}.json"
        
        with open(filename, "w") as f:
            f.write(analysis_result.model_dump_json(indent=2))
        
        # Return HTTP 403 Forbidden if risk is HIGH or CRITICAL
        if analysis_result.metadata.risk_level in ["HIGH", "CRITICAL"]:
            return JSONResponse(
                status_code=403, 
                content=analysis_result.model_dump()
            )
            
        return analysis_result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection Engine Error: {str(e)}")
