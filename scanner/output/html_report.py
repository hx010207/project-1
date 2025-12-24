"""
HTML report generation for professional security reports
"""

from pathlib import Path
from datetime import datetime
from typing import Dict

from scanner.core.scanner_engine import ScanResult, ScanStatus
from scanner.intelligence.risk_scoring import RiskLevel


class HTMLReporter:
    """Generate professional HTML security reports"""
    
    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background:  linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        . header . subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .content {{ padding: 30px; }}
        .section {{
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }}
        .section h2 {{
            color: #1e3c72;
            margin-bottom: 15px;
            font-size: 1.8em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin:  20px 0;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .summary-card . label {{
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        .summary-card .value {{
            font-size: 1.8em;
            font-weight:  bold;
            color: #1e3c72;
        }}
        .risk-critical {{ border-left-color: #dc3545 ! important; color: #dc3545 !important; }}
        .risk-high {{ border-left-color: #fd7e14 !important; color: #fd7e14 !important; }}
        .risk-medium {{ border-left-color: #ffc107 !important; color: #ffc107 !important; }}
        .risk-low {{ border-left-color: #28a745 !important; color: #28a745 !important; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        table thead {{
            background: #1e3c72;
            color: white;
        }}
        table th, table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        table tbody tr:hover {{
            background:  #f8f9fa;
        }}
        . status-open {{ color: #28a745; font-weight: bold; }}
        .status-closed {{ color: #dc3545; }}
        .status-filtered {{ color: #ffc107; }}
        .recommendations {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        .recommendations ul {{
            list-style: none;
            padding-left: 0;
        }}
        .recommendations li {{
            padding: 8px 0;
            padding-left: 25px;
            position: relative;
        }}
        .recommendations li:before {{
            content: "🛡️";
            position:  absolute;
            left: 0;
        }}
        .vulnerability {{
            background: #f8d7da;
            border: 1px solid #dc3545;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }}
        .vulnerability . cve-id {{
            font-weight: bold;
            color: #dc3545;
            font-size: 1.1em;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #dee2e6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <div class="subtitle">Advanced Network Port Scanner & Vulnerability Assessment</div>
            <div style="margin-top: 15px; font-size: 0.9em;">
                Target: {target} | Generated: {timestamp}
            </div>
        </div>
        
        <div class="content">
            <!-- Summary Section -->
            <div class="section">
                <h2>📊 Scan Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <div class="label">Duration</div>
                        <div class="value">{duration}s</div>
                    </div>
                    <div class="summary-card">
                        <div class="label">Ports Scanned</div>
                        <div class="value">{ports_scanned}</div>
                    </div>
                    <div class="summary-card">
                        <div class="label">Open Ports</div>
                        <div class="value">{open_ports}</div>
                    </div>
                    <div class="summary-card {risk_class}">
                        <div class="label">Overall Risk</div>
                        <div class="value">{overall_risk}</div>
                    </div>
                </div>
            </div>
            
            <!-- Open Ports Section -->
            <div class="section">
                <h2>🔓 Open Ports</h2>
                {open_ports_table}
            </div>
            
            <!-- Vulnerabilities Section -->
            {vulnerabilities_section}
            
            <!-- Recommendations Section -->
            <div class="section">
                <h2>🛡️ Security Recommendations</h2>
                <div class="recommendations">
                    <ul>
                        {recommendations}
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by Advanced Network Port Scanner v1.0.0</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                ⚠️ This report contains sensitive security information. Handle with care.
            </p>
        </div>
    </div>
</body>
</html>
    """
    
    @staticmethod
    def generate(scan_result: ScanResult, 
                 risk_assessment: Dict = None,
                 output_file: str = "scan_report.html") -> str:
        """
        Generate HTML report
        
        Args:
            scan_result: Scan results
            risk_assessment: Risk assessment data
            output_file: Output file path
        
        Returns:
            Path to generated report
        """
        # Build open ports table
        open_ports_rows = []
        for port in scan_result.open_ports:
            open_ports_rows.append(f"""
                <tr>
                    <td>{port.port}</td>
                    <td>{port.protocol. upper()}</td>
                    <td class="status-open">OPEN</td>
                    <td>{port.service or 'unknown'}</td>
                    <td>{port.version or '-'}</td>
                    <td>{port.response_time:. 3f}s if port.response_time else '-'}</td>
                </tr>
            """)
        
        open_ports_table = f"""
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Version</th>
                        <th>Response Time</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(open_ports_rows) if open_ports_rows else '<tr><td colspan="6" style="text-align: center;">No open ports found</td></tr>'}
                </tbody>
            </table>
        """
        
        # Build vulnerabilities section
        vulnerabilities_section = ""
        if scan_result.vulnerabilities:
            vuln_items = []
            for vuln in scan_result.vulnerabilities[: 15]: 
                vuln_items.append(f"""
                    <div class="vulnerability">
                        <div class="cve-id">{vuln.get('cve_id', 'N/A')}</div>
                        <div><strong>Severity:</strong> {vuln.get('severity', 'UNKNOWN')}</div>
                        <div><strong>Service:</strong> {vuln.get('service', 'N/A')} {vuln.get('version', '')}</div>
                        <div><strong>Description:</strong> {vuln.get('description', 'No description available')}</div>
                        {f"<div><strong>CVSS Score:</strong> {vuln. get('cvss_score')}</div>" if vuln.get('cvss_score') else ''}
                    </div>
                """)
            
            vulnerabilities_section = f"""
                <div class="section">
                    <h2>⚠️ Vulnerabilities Detected</h2>
                    {''.join(vuln_items)}
                </div>
            """
        
        # Build recommendations
        recommendations_html = ""
        if risk_assessment and risk_assessment.get('recommendations'):
            recommendations_html = '\n'.join(
                f"<li>{rec}</li>"
                for rec in risk_assessment['recommendations']
            )
        else:
            recommendations_html = "<li>No specific recommendations at this time.</li>"
        
        # Determine risk class
        risk_class = ""
        overall_risk = "INFO"
        if risk_assessment: 
            risk_level = risk_assessment.get('overall_risk', RiskLevel.INFO)
            if hasattr(risk_level, 'name'):
                overall_risk = risk_level.name
                risk_class = f"risk-{risk_level. name.lower()}"
        
        # Populate template
        html_content = HTMLReporter.HTML_TEMPLATE. format(
            target=scan_result.target,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration=f"{scan_result.duration:. 2f}",
            ports_scanned=scan_result.ports_scanned,
            open_ports=len(scan_result.open_ports),
            overall_risk=overall_risk,
            risk_class=risk_class,
            open_ports_table=open_ports_table,
            vulnerabilities_section=vulnerabilities_section,
            recommendations=recommendations_html
        )
        
        # Write to file
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)


def generate_report(scan_result: ScanResult, output_file: str = "report.html", risk_assessment: Dict = None) -> str:
    """Convenience function for HTML report generation"""
    return HTMLReporter.generate(scan_result, risk_assessment, output_file)