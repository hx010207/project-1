"""
Core scanning engine with multiple protocol support
"""

import asyncio
import time
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

from scanner.utils.logger import get_logger
from scanner. core.concurrency_manager import ConcurrencyManager
from scanner.core.timeout_handler import TimeoutHandler
from scanner.utils.rate_limiter import RateLimiter


class ScanStatus(Enum):
    """Port status enumeration"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


@dataclass
class PortResult:
    """Single port scan result"""
    port: int
    status: ScanStatus
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    response_time: Optional[float] = None
    protocol: str = "tcp"
    extra_info: Dict = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan results for a target"""
    target: str
    start_time: float
    end_time: float
    scan_type: str
    ports_scanned: int
    ports:  List[PortResult] = field(default_factory=list)
    os_fingerprint: Optional[Dict] = None
    vulnerabilities: List[Dict] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time
    
    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.status == ScanStatus. OPEN]
    
    @property
    def closed_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.status == ScanStatus. CLOSED]
    
    @property
    def filtered_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.status == ScanStatus.FILTERED]


class ScannerEngine:
    """Core scanning orchestration engine"""
    
    def __init__(self,
                 concurrency: int = 500,
                 timeout: float = 5.0,
                 max_rate: int = 1000,
                 timing_profile: str = 'normal'):
        """
        Initialize scanner engine
        
        Args: 
            concurrency: Maximum concurrent scans
            timeout: Base timeout for connections
            max_rate: Maximum packets per second
            timing_profile: Timing profile name
        """
        self.logger = get_logger()
        
        self.concurrency_manager = ConcurrencyManager(
            max_workers=concurrency,
            min_workers=min(50, concurrency // 10)
        )
        
        self. timeout_handler = TimeoutHandler(base_timeout=timeout)
        self.rate_limiter = RateLimiter(max_rate=max_rate)
        
        # Scan configuration
        self.timing_profile = timing_profile
        self.scan_callbacks:  List[Callable] = []
        
        # Statistics
        self.total_scans = 0
        self.total_open_ports = 0
    
    async def scan(self,
                   target: str,
                   ports: List[int],
                   scan_func: Callable,
                   scan_type: str = "tcp") -> ScanResult:
        """
        Execute port scan on target
        
        Args:
            target: Target IP address
            ports: List of ports to scan
            scan_func:  Async function(host, port) -> PortResult
            scan_type:  Type of scan being performed
        
        Returns: 
            ScanResult object with all findings
        """
        start_time = time.time()
        self.logger.scan_start(target, scan_type)
        
        # Create scan tasks
        tasks = []
        for port in ports:
            task = self._scan_port_wrapper(target, port, scan_func)
            tasks.append(task)
        
        # Execute with progress tracking
        results = []
        for i, coro in enumerate(asyncio.as_completed(tasks), 1):
            try:
                result = await coro
                if result: 
                    results.append(result)
                    
                    # Fire callbacks for open ports
                    if result.status == ScanStatus.OPEN: 
                        for callback in self.scan_callbacks:
                            await callback(target, result)
                
                # Progress update every 100 ports
                if i % 100 == 0:
                    self.logger.debug(f"Progress: {i}/{len(ports)} ports scanned")
            
            except Exception as e:
                self.logger.error(f"Error scanning port:  {e}")
        
        # Build final result
        end_time = time.time()
        scan_result = ScanResult(
            target=target,
            start_time=start_time,
            end_time=end_time,
            scan_type=scan_type,
            ports_scanned=len(ports),
            ports=results
        )
        
        # Update statistics
        self.total_scans += 1
        self. total_open_ports += len(scan_result.open_ports)
        
        self.logger.scan_complete(
            target,
            scan_result.duration,
            len(scan_result.open_ports)
        )
        
        return scan_result
    
    async def _scan_port_wrapper(self,
                                   host: str,
                                   port: int,
                                   scan_func: Callable) -> Optional[PortResult]:
        """Wrapper for individual port scan with rate limiting and concurrency control"""
        await self.concurrency_manager.acquire()
        await self.rate_limiter.acquire()
        
        try: 
            # Execute scan with timeout
            start = time.monotonic()
            result = await self.timeout_handler.with_timeout(
                scan_func(host, port),
                host,
                port
            )
            elapsed = time.monotonic() - start
            
            # Record RTT for adaptive timeout
            self.timeout_handler. record_rtt(host, elapsed, port)
            self.rate_limiter.report_success()
            
            return result
        
        except asyncio.TimeoutError:
            self.rate_limiter.report_error()
            return PortResult(
                port=port,
                status=ScanStatus.FILTERED,
                response_time=self.timeout_handler.get_timeout(host, port)
            )
        
        except Exception as e:
            self. rate_limiter.report_error()
            self.logger.debug(f"Error on {host}:{port} - {e}")
            return None
        
        finally:
            self. concurrency_manager.release()
    
    def register_callback(self, callback: Callable):
        """Register callback for open port discoveries"""
        self.scan_callbacks.append(callback)
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics"""
        return {
            'total_scans': self. total_scans,
            'total_open_ports': self. total_open_ports,
            'concurrency':  self.concurrency_manager.get_stats()
        }