from src.models.features import DetectionDetail
import datetime
from typing import List
from src.models import RequestModel, FeaturesModel, AnalysisResultModel, MetadataModel
from src.extractor import extract_sqli, extract_xss, extract_path_traversal, extract_command_injection
from src.detector.utils import remove_duplicates
from .sql_injection import detect_sqli
from .xss import detect_xss
from .path_traversal import detect_path_traversal
from .command_injection import detect_command_injection

def extract_features(payload_str: str, location: str, detector_function) -> List[DetectionDetail]:
        if not payload_str:
            return []
        all_detection = []            
        sqli_feat = detector_function(payload_str)
        for f in sqli_feat: 
            f.location = location
            all_detection.append(f)
        return all_detection

def run_detection_engine(request: RequestModel) -> AnalysisResultModel:
    payloads = {
        "url": request.url,
        "body": request.body,
        "params": request.params or {},
        "headers": request.headers or {},
    }
    
    sqli_all = []
    xss_all = []
    pt_all = []
    ci_all = []
    
    def process_content(payload_str: str, location: str):
        if not payload_str:
            return
        
        try:
            import json
            data = json.loads(payload_str)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, str):
                        process_content(str(v), f"{location}.{k}")
                return
        except Exception:
            pass

        sqli_all.extend(extract_features(payload_str, location, extract_sqli))
        xss_all.extend(extract_features(payload_str, location, extract_xss))
        pt_all.extend(extract_features(payload_str, location, extract_path_traversal))
        ci_all.extend(extract_features(payload_str, location, extract_command_injection))

    for section, content in payloads.items():
        if isinstance(content, dict):
            for key, val in content.items():
                process_content(str(val), f"{section}.{key}")
        elif content:
            process_content(str(content), section)
            
    sqli_all = remove_duplicates(sqli_all)
    xss_all = remove_duplicates(xss_all)
    pt_all = remove_duplicates(pt_all)
    ci_all = remove_duplicates(ci_all)
            
    all_details = sqli_all + xss_all + pt_all + ci_all
    all_patterns = [d.pattern for d in all_details]
    
    features = FeaturesModel(
        detected_keywords=all_patterns,
        suspicious_patterns=all_patterns,
        encoding="None",
        detailed_detections=all_details
    )
    
    detections = []
    if det := detect_sqli(sqli_all): detections.append(det)
    if det := detect_xss(xss_all): detections.append(det)
    if det := detect_path_traversal(pt_all): detections.append(det)
    if det := detect_command_injection(ci_all): detections.append(det)
    
    risk_level = "LOW"
    if detections:
        max_conf = max(d.confidence for d in detections)
        if max_conf >= 0.7:
            risk_level = "CRITICAL"
        elif max_conf >= 0.4:
            risk_level = "HIGH"
        else:
            risk_level = "MEDIUM"

    metadata = MetadataModel(
        risk_level=risk_level,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    
    return AnalysisResultModel(
        request=request,
        features=features,
        detections=detections,
        metadata=metadata
    )
