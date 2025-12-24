"""
JSON export functionality for machine-readable output
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from scanner.core.scanner_engine import ScanResult, PortResult, ScanStatus


class JSONExporter: 
    """Export scan results to JSON format"""
    
    @staticmethod
    def export(scan_result: ScanResult, 
               risk_assessment: Dict = None,
               output_file: str = None) -> str:
        """
        Export scan results to JSON
        
        Args:
            scan_result: Scan results to export
            risk_assessment: Risk assessment data
            output_file: Output file path (if None, returns JSON string)
        
        Returns:
            JSON string or file path
        """
        data = JSONExporter._build_json_structure(scan_result, risk_assessment)
        
        json_str = json.dumps(data, indent=2, default=str)
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                f.write(json_str)
            
            return str(output_path)
        
        return json_str
    
    @staticmethod
    def _build_json_structure(scan_result: ScanResult, risk_assessment: Dict = None) -> Dict[str, Any]:
        """Build JSON data structure"""
        data = {
            "scan_metadata": {
                "target": scan_result.target,
                "scan_type": scan_result.scan_type,
                "start_time": datetime.fromtimestamp(scan_result.start_time).isoformat(),
                "end_time": datetime.fromtimestamp(scan_result.end_time).isoformat(),
                "duration_seconds": scan_result.duration,
                "ports_scanned":  scan_result.ports_scanned
            },
            "summary": {
                "total_ports": scan_result.ports_scanned,
                "open_ports": len(scan_result.open_ports),
                "closed_ports":  len(scan_result.closed_ports),
                "filtered_ports": len(scan_result.filtered_ports)
            },
            "ports":  [
                JSONExporter._port_to_dict(port)
                for port in scan_result.ports
            ],
            "open_ports_detail": [
                JSONExporter._port_to_dict(port)
                for port in scan_result.open_ports
            ]
        }
        
        # Add risk assessment
        if risk_assessment:
            data["risk_assessment"] = {
                "overall_risk": risk_assessment.get('overall_risk', 'UNKNOWN').name if hasattr(risk_assessment. get('overall_risk'), 'name') else str(risk_assessment.get('overall_risk')),
                "total_score": risk_assessment.get('total_score', 0),
                "average_score": risk_assessment.get('average_score', 0),
                "attack_surface": risk_assessment.get('attack_surface', 'unknown'),
                "critical_issues": risk_assessment.get('critical_issues', []),
                "recommendations": risk_assessment.get('recommendations', [])
            }
        
        # Add vulnerabilities
        if scan_result. vulnerabilities:
            data["vulnerabilities"] = [
                {
                    "cve_id":  v.get('cve_id'),
                    "severity": v. get('severity'),
                    "service": v.get('service'),
                    "version": v.get('version'),
                    "description": v.get('description'),
                    "cvss_score": v.get('cvss_score')
                }
                for v in scan_result.vulnerabilities
            ]
        
        # Add OS fingerprint
        if scan_result.os_fingerprint:
            data["os_fingerprint"] = scan_result.os_fingerprint
        
        return data
    
    @staticmethod
    def _port_to_dict(port:  PortResult) -> Dict:
        """Convert PortResult to dictionary"""
        return {
            "port": port. port,
            "status": port.status.value if isinstance(port.status, ScanStatus) else str(port.status),
            "protocol": port.protocol,
            "service": port.service,
            "version": port.version,
            "banner": port. banner,
            "response_time": port.response_time,
            "extra_info": port.extra_info
        }


def export_json(scan_result: ScanResult, output_file: str = None, risk_assessment: Dict = None) -> str:
    """Convenience function for JSON export"""
    return JSONExporter.export(scan_result, risk_assessment, output_file)