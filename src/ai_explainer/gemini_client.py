import os
from google import genai
from google.genai import types
from src.models import AnalysisResultModel

PROMPT_TEMPLATE = """You are a senior cybersecurity analyst.

Given the following analysis JSON:
```json
{json_data}
```

Write a security report with the following sections:
1. Executive Summary
2. Attack Type
    - Name
    - Confidence
3. Why it was detected
    - Evidence
    - Location
    - Patterns
    - Reasoning
4. Potential Impact
5. Severity
6. Recommended Mitigations
7. Analyst Notes

Strict Constraint: Only use the information provided in the JSON. 
Do not invent attacks, features, or details that are not explicitly listed in the source data.
"""

async def generate_security_report(analysis: AnalysisResultModel) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "Error: GEMINI_API_KEY environment variable is not set."
    
    try:
        client = genai.Client(api_key=api_key)
        json_data = analysis.model_dump_json(indent=2)
        prompt = PROMPT_TEMPLATE.format(json_data=json_data)
        
        model_name = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
        # Use the asynchronous aio client
        response = await client.aio.models.generate_content(
            model=model_name,
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"Error generating report: {str(e)}"
