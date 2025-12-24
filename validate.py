#!/usr/bin/env python3
"""
Validation script to ensure all components are properly integrated
"""

import sys
import importlib
from pathlib import Path


def validate_imports():
    """Validate all module imports"""
    modules = [
        'scanner',
        'scanner.core. scanner_engine',
        'scanner.core.concurrency_manager',
        'scanner.core.timeout_handler',
        'scanner.scan_types. tcp_connect',
        'scanner.scan_types.tcp_syn',
        'scanner.scan_types.udp_scan',
        'scanner.scan_types. stealth_scan',
        'scanner.detection.banner_grabber',
        'scanner.detection. service_fingerprint',
        'scanner.detection.os_fingerprint',
        'scanner.intelligence. cve_mapper',
        'scanner.intelligence.risk_scoring',
        'scanner.output.cli_renderer',
        'scanner. output.json_exporter',
        'scanner.output.html_report',
        'scanner.utils.logger