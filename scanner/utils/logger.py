"""
Advanced logging system with multiple output formats
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)


class SecurityLogger:
    """Enhanced logger for security operations"""
    
    SEVERITY_COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    
    def __init__(self, name: str, log_file: Optional[str] = None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Console handler with colors
        console_handler = logging. StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = self._ColoredFormatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler. setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    class _ColoredFormatter(logging. Formatter):
        """Custom formatter with color support"""
        
        def format(self, record):
            levelname = record.levelname
            color = SecurityLogger.SEVERITY_COLORS. get(levelname, '')
            record.levelname = f"{color}{levelname}{Style. RESET_ALL}"
            return super().format(record)
    
    def debug(self, msg: str):
        self.logger.debug(msg)
    
    def info(self, msg: str):
        self.logger.info(msg)
    
    def warning(self, msg: str):
        self.logger.warning(msg)
    
    def error(self, msg:  str):
        self.logger. error(msg)
    
    def critical(self, msg: str):
        self.logger.critical(msg)
    
    def scan_start(self, target: str, scan_type: str):
        """Log scan initiation"""
        self.info(f"🎯 Starting {scan_type} scan on {target}")
    
    def scan_complete(self, target: str, duration: float, ports_found: int):
        """Log scan completion"""
        self.info(f"✅ Scan complete:  {target} | Duration: {duration:.2f}s | Open ports: {ports_found}")
    
    def vulnerability_found(self, severity: str, description: str):
        """Log vulnerability discovery"""
        emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
        self. warning(f"{emoji} {severity}:  {description}")


# Global logger instance
def get_logger(name: str = "scanner", log_file: Optional[str] = None) -> SecurityLogger:
    """Get or create logger instance"""
    return SecurityLogger(name, log_file)