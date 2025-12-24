"""
Main CLI entry point for the scanner
Handles argument parsing, orchestration, and execution
"""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import List, Optional

from scanner import show_disclaimer, DISCLAIMER
from scanner.utils. logger import get_logger
from scanner.utils.ip_range_parser import IPRangeParser
from scanner. utils.rate_limiter import TimingProfile
from scanner.core.scanner_engine import ScannerEngine, ScanResult
from scanner.scan_types import tcp_connect, tcp_syn, udp_scan, stealth_scan
from scanner.detection.banner_grabber import BannerGrabber
from scanner.detection.service_fingerprint import ServiceFingerprinter
from scanner.detection.os_fingerprint import OSFingerprinter
from scanner.intelligence.cve_mapper import CVEMapper
from scanner. intelligence.risk_scoring import RiskScorer
from scanner.output.cli_renderer import CLIRenderer
from scanner. output.json_exporter import JSONExporter
from scanner.output.html_report import HTMLReporter


class PortScanner:
    """Main scanner orchestrator"""
    
    # Common port ranges
    PORT_RANGES = {
        'fast': list(range(1, 100)) + [443, 445, 3306, 3389, 5432, 8080, 8443],
        'common': list(range(1, 1024)),
        'full': list(range(1, 65536)),
        'top100': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                   1723, 3306, 3389, 5900, 8080] + list(range(135, 140)) + list(range(1024, 1100)),
    }
    
    def __init__(self, args):
        self.args = args
        self.logger = get_logger(log_file=args.log_file if hasattr(args, 'log_file') else None)
        self.renderer = CLIRenderer()
        self.scan_results = []
    
    async def run(self):
        """Main execution flow"""
        try:
            # Show banner
            if not self.args.quiet:
                self.renderer.render_banner()
                
                if not self.args.accept_disclaimer:
                    show_disclaimer()
                    response = input("\n Do you accept these terms? (yes/no): ")
                    if response.lower() not in ['yes', 'y']: 
                        self.renderer.render_error("Disclaimer not accepted.  Exiting.")
                        sys.exit(1)
            
            # Parse targets
            targets = self._parse_targets()
            
            # Validate targets
            if self.args.safe_mode:
                targets = self._validate_safe_targets(targets)
            
            # Parse ports
            ports = self._parse_ports()
            
            # Select scan type
            scan_func = self._select_scan_type()
            
            # Configure scanner
            timing = TimingProfile. get_profile(self.args.timing)
            scanner = ScannerEngine(
                concurrency=self.args.concurrency,
                timeout=timing['timeout'],
                max_rate=timing['max_rate'],
                timing_profile=self.args.timing
            )
            
            # Register banner grabbing callback
            if self.args.service_detection:
                async def banner_callback(host, port_result):
                    enriched = await BannerGrabber.enrich_port_result(host, port_result)
                    # Identify service
                    service, version = ServiceFingerprinter. identify_service(
                        enriched. port,
                        enriched.banner
                    )
                    port_result.service = service
                    port_result.version = version
                
                scanner.register_callback(banner_callback)
            
            # Execute scans
            for target in targets:
                if not self.args.quiet:
                    self.renderer.render_scan_start(target, ports, self.args.scan_type)
                
                # Perform scan
                scan_result = await scanner.scan(
                    target=target,
                    ports=ports,
                    scan_func=scan_func,
                    scan_type=self.args.scan_type
                )
                
                # Vulnerability assessment
                if self.args. vuln_scan:
                    await self._perform_vulnerability_scan(scan_result)
                
                # Risk assessment
                risk_assessment = None
                if self.args.risk_assessment:
                    risk_assessment = RiskScorer.score_scan_result(scan_result)
                
                # Store results
                self.scan_results.append((scan_result, risk_assessment))
                
                # Render results
                if not self.args.quiet:
                    self.renderer. render_scan_result(scan_result, risk_assessment)
                
                # Export results
                await self._export_results(scan_result, risk_assessment)
            
            if not self.args.quiet:
                self.renderer.render_success("Scan completed successfully!")
        
        except KeyboardInterrupt: 
            self.renderer.render_warning("Scan interrupted by user")
            sys.exit(130)
        
        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            self.renderer.render_error(f"Fatal error: {e}")
            if self.args.debug:
                raise
            sys.exit(1)
    
    def _parse_targets(self) -> List[str]:
        """Parse target specifications"""
        targets = []
        
        # From command line
        if self.args.target:
            targets.extend(IPRangeParser.parse(self.args.target))
        
        # From file
        if self.args.target_file:
            with open(self.args.target_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.extend(IPRangeParser.parse(line))
        
        if not targets:
            raise ValueError("No targets specified.  Use -t or -T")
        
        return targets
    
    def _validate_safe_targets(self, targets: List[str]) -> List[str]:
        """Validate targets in safe mode"""
        import ipaddress
        
        safe_targets = []
        for target in targets:
            try: 
                ip = ipaddress. IPv4Address(target)
                
                # Block public IPs in safe mode
                if not (ip.is_private or ip. is_loopback):
                    self.renderer.render_warning(
                        f"Skipping public IP {target} (safe mode enabled)"
                    )
                    continue
                
                safe_targets.append(target)
            
            except: 
                safe_targets.append(target)  # Hostname, allow
        
        return safe_targets
    
    def _parse_ports(self) -> List[int]:
        """Parse port specifications"""
        if self.args.port_range:
            # Named range
            if self.args.port_range in self.PORT_RANGES: 
                return self.PORT_RANGES[self.args.port_range]
            
            # Custom range (e.g., "1-1000")
            if '-' in self.args.port_range:
                start, end = map(int, self.args.port_range.split('-'))
                return list(range(start, end + 1))
            
            # Single port
            return [int(self.args.port_range)]
        
        # Specific ports
        if self.args.ports:
            ports = []
            for spec in self.args.ports. split(','):
                if '-' in spec:
                    start, end = map(int, spec.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(spec))
            return ports
        
        # Default
        return self.PORT_RANGES['common']
    
    def _select_scan_type(self):
        """Select scan function based on type"""
        scan_types = {
            'tcp':  tcp_connect. scan,
            'syn': tcp_syn.scan,
            'udp': udp_scan.scan,
            'stealth': stealth_scan.scan,
        }
        
        return scan_types.get(self. args.scan_type, tcp_connect.scan)
    
    async def _perform_vulnerability_scan(self, scan_result: ScanResult):
        """Perform vulnerability assessment"""
        vulnerabilities = []
        
        for port in scan_result.open_ports:
            if port. service and port.version:
                cves = CVEMapper.find_cves(port.service, port.version)
                
                for cve in cves:
                    vulnerabilities.append({
                        'port': port.port,
                        'service': port.service,
                        'version': port.version,
                        'cve_id':  cve.cve_id,
                        'severity': cve.severity,
                        'description': cve.description,
                        'cvss_score': cve.cvss_score
                    })
        
        scan_result.vulnerabilities = vulnerabilities
    
    async def _export_results(self, scan_result: ScanResult, risk_assessment: Optional[dict]):
        """Export results in requested formats"""
        if self.args.output_json:
            json_file = JSONExporter.export(
                scan_result,
                risk_assessment,
                self.args.output_json
            )
            if not self.args.quiet:
                self.renderer.render_success(f"JSON report saved:  {json_file}")
        
        if self.args.output_html:
            html_file = HTMLReporter.generate(
                scan_result,
                risk_assessment,
                self.args. output_html
            )
            if not self.args.quiet:
                self.renderer.render_success(f"HTML report saved:  {html_file}")


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Advanced Network Port Scanner & Vulnerability Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fast scan on common ports
  python -m scanner.main -t 192.168.1.1 --port-range fast
  
  # Full TCP scan with service detection
  python -m scanner. main -t 192.168.1.0/24 --port-range full -sV
  
  # Stealth scan with timing
  python -m scanner.main -t example.com --scan-type stealth --timing sneaky
  
  # Vulnerability assessment with reports
  python -m scanner.main -t 10.0.0.1 -sV --vuln --output-html report.html
        """
    )
    
    # Target specification
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument('-t', '--target', help='Target IP, hostname, or CIDR (e.g., 192.168.1.1, 192.168.1.0/24)')
    target_group.add_argument('-T', '--target-file', help='File containing target list')
    
    # Port specification
    port_group = parser. add_argument_group('Port Specification')
    port_group.add_argument('-p', '--ports', help='Ports to scan (e.g., 22,80,443 or 1-1000)')
    port_group.add_argument('--port-range', default='common',
                           choices=['fast', 'common', 'full', 'top100'],
                           help='Predefined port range (default: common)')
    
    # Scan type
    scan_group = parser.add_argument_group('Scan Type')
    scan_group.add_argument('--scan-type', default='tcp',
                           choices=['tcp', 'syn', 'udp', 'stealth'],
                           help='Scan technique (default: tcp)')
    
    # Timing and performance
    perf_group = parser.add_argument_group('Performance')
    perf_group.add_argument('--timing', default='normal',
                           choices=['paranoid', 'sneaky', 'polite', 'normal', 'aggressive', 'insane'],
                           help='Timing template (default: normal)')
    perf_group.add_argument('--concurrency', type=int, default=500,
                           help='Maximum concurrent connections (default: 500)')
    
    # Detection
    detect_group = parser.add_argument_group('Detection')
    detect_group.add_argument('-sV', '--service-detection', action='store_true',
                             help='Enable service/version detection')
    detect_group.add_argument('--os-detection', action='store_true',
                             help='Enable OS fingerprinting')
    
    # Vulnerability scanning
    vuln_group = parser.add_argument_group('Vulnerability Assessment')
    vuln_group.add_argument('--vuln', '--vuln-scan', dest='vuln_scan', action='store_true',
                           help='Enable vulnerability scanning')
    vuln_group.add_argument('--risk-assessment', action='store_true', default=True,
                           help='Perform risk assessment (default: enabled)')
    
    # Output
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-oJ', '--output-json', help='Save results as JSON')
    output_group.add_argument('-oH', '--output-html', help='Generate HTML report')
    output_group.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    output_group.add_argument('--log-file', help='Log file path')
    
    # Safety
    safety_group = parser.add_argument_group('Safety')
    safety_group.add_argument('--safe-mode', action='store_true',
                             help='Block scanning of public IPs')
    safety_group.add_argument('--accept-disclaimer', action='store_true',
                             help='Accept legal disclaimer without prompt')
    
    # Debug
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Create scanner instance
    scanner = PortScanner(args)
    
    # Run async scanner
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt: 
        print("\n[! ] Scan interrupted by user")
        sys.exit(130)


if __name__ == '__main__':
    main()