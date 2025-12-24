"""
CLI rendering with colorized output and progress tracking
"""

import sys
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text
from rich.live import Live

from scanner.core.scanner_engine import ScanResult, PortResult, ScanStatus
from scanner.intelligence.risk_scoring import RiskLevel


class CLIRenderer:
    """Rich CLI output renderer"""
    
    def __init__(self):
        self.console = Console()
    
    def render_banner(self):
        """Display tool banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     Advanced Network Port Scanner & Vulnerability Tool          ║
║                  Professional Security Assessment                ║
║                         Version 1.0.0                            ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")
    
    def render_scan_start(self, target: str, ports: List[int], scan_type: str):
        """Display scan initiation info"""
        info = f"""
[bold green]🎯 Scan Target:[/bold green] {target}
[bold green]📡 Scan Type:[/bold green] {scan_type. upper()}
[bold green]🔢 Port Range:[/bold green] {len(ports)} ports ({min(ports)}-{max(ports)})
[bold green]⏰ Started:[/bold green] {self._get_timestamp()}
        """
        self.console.print(Panel(info, title="Scan Configuration", border_style="green"))
    
    def create_progress_bar(self, total: int):
        """Create progress bar for scanning"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        )
    
    def render_port_result(self, port_result: PortResult, risk_data: Dict = None):
        """Render single port result"""
        status_colors = {
            ScanStatus. OPEN: "green",
            ScanStatus.CLOSED: "red",
            ScanStatus. FILTERED: "yellow",
            ScanStatus.UNKNOWN: "dim"
        }
        
        color = status_colors.get(port_result.status, "white")
        
        service_info = f"{port_result.service or 'unknown'}"
        if port_result.version:
            service_info += f" ({port_result.version})"
        
        risk_indicator = ""
        if risk_data and port_result.status == ScanStatus.OPEN: 
            risk_level = risk_data.get('risk_level', RiskLevel.INFO)
            risk_icons = {
                RiskLevel. CRITICAL: "🔴",
                RiskLevel.HIGH:  "🟠",
                RiskLevel. MEDIUM: "🟡",
                RiskLevel.LOW: "🟢",
                RiskLevel.INFO:  "⚪"
            }
            risk_indicator = risk_icons. get(risk_level, "")
        
        self.console. print(
            f"{risk_indicator} Port [bold]{port_result.port}[/bold] "
            f"[{color}]{port_result.status.value. upper()}[/{color}] - {service_info}"
        )
        
        if port_result.banner and len(port_result.banner) > 0:
            banner_preview = port_result.banner[:80] + "..." if len(port_result.banner) > 80 else port_result.banner
            self.console.print(f"   └─ Banner: [dim]{banner_preview}[/dim]")
    
    def render_scan_result(self, scan_result: ScanResult, risk_assessment: Dict = None):
        """Render complete scan results"""
        self.console.print("\n")
        self.console.rule("[bold blue]Scan Results[/bold blue]")
        
        # Summary table
        summary_table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        summary_table. add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Target", scan_result.target)
        summary_table.add_row("Duration", f"{scan_result.duration:.2f}s")
        summary_table.add_row("Ports Scanned", str(scan_result.ports_scanned))
        summary_table. add_row("Open Ports", str(len(scan_result.open_ports)))
        summary_table.add_row("Closed Ports", str(len(scan_result.closed_ports)))
        summary_table.add_row("Filtered Ports", str(len(scan_result.filtered_ports)))
        
        if risk_assessment:
            overall_risk = risk_assessment.get('overall_risk', RiskLevel.INFO)
            risk_color = {
                RiskLevel.CRITICAL: "red",
                RiskLevel.HIGH: "orange1",
                RiskLevel. MEDIUM: "yellow",
                RiskLevel.LOW: "green",
                RiskLevel.INFO:  "white"
            }.get(overall_risk, "white")
            
            summary_table.add_row(
                "Overall Risk",
                f"[{risk_color}]{overall_risk.name}[/{risk_color}]"
            )
            summary_table.add_row(
                "Attack Surface",
                risk_assessment.get('attack_surface', 'N/A').upper()
            )
        
        self.console.print(summary_table)
        
        # Open ports detail
        if scan_result.open_ports:
            self.console.print("\n")
            ports_table = Table(title="🔓 Open Ports", show_header=True, header_style="bold green")
            ports_table.add_column("Port", style="cyan", justify="right")
            ports_table.add_column("Service", style="yellow")
            ports_table.add_column("Version", style="magenta")
            ports_table.add_column("Risk", style="red")
            ports_table.add_column("Issues", style="dim")
            
            for port in scan_result. open_ports:
                risk_info = ""
                issues = ""
                
                if risk_assessment:
                    from scanner.intelligence.risk_scoring import RiskScorer
                    port_risk = RiskScorer. score_port(port)
                    risk_info = port_risk['risk_level'].name
                    issues = ", ".join(port_risk['issues'][:2]) if port_risk['issues'] else "-"
                
                ports_table.add_row(
                    str(port. port),
                    port.service or "unknown",
                    port.version or "-",
                    risk_info,
                    issues
                )
            
            self.console.print(ports_table)
        
        # Vulnerabilities
        if scan_result. vulnerabilities:
            self.console.print("\n")
            vuln_table = Table(title="⚠️  Vulnerabilities", show_header=True, header_style="bold red")
            vuln_table. add_column("CVE ID", style="red")
            vuln_table. add_column("Severity", style="yellow")
            vuln_table.add_column("Service", style="cyan")
            vuln_table. add_column("Description", style="white")
            
            for vuln in scan_result.vulnerabilities[: 10]:  # Show top 10
                vuln_table.add_row(
                    vuln.get('cve_id', 'N/A'),
                    vuln.get('severity', 'UNKNOWN'),
                    vuln. get('service', 'N/A'),
                    vuln.get('description', '')[: 50] + "..."
                )
            
            self.console.print(vuln_table)
        
        # Recommendations
        if risk_assessment and risk_assessment.get('recommendations'):
            self.console.print("\n")
            rec_panel = Panel(
                "\n". join(f"• {rec}" for rec in risk_assessment['recommendations'][:8]),
                title="🛡️  Security Recommendations",
                border_style="yellow"
            )
            self.console.print(rec_panel)
    
    def render_error(self, message: str):
        """Display error message"""
        self.console.print(f"[bold red]❌ Error:[/bold red] {message}")
    
    def render_warning(self, message:  str):
        """Display warning message"""
        self.console.print(f"[bold yellow]⚠️  Warning:[/bold yellow] {message}")
    
    def render_success(self, message: str):
        """Display success message"""
        self.console.print(f"[bold green]✅ {message}[/bold green]")
    
    @staticmethod
    def _get_timestamp():
        """Get current timestamp"""
        from datetime import datetime
        return datetime. now().strftime("%Y-%m-%d %H:%M:%S")