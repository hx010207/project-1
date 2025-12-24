"""
Stealth scanning techniques with randomization and evasion
"""

import asyncio
import random
import time
from typing import List

from scanner.core.scanner_engine import PortResult, ScanStatus
from scanner.scan_types.tcp_syn import scan as syn_scan


class StealthScanner:
    """
    Stealth scan implementation with IDS/IPS evasion techniques: 
    - Random port order
    - Random timing delays
    - Packet size randomization
    - TTL manipulation (for advanced scenarios)
    """
    
    def __init__(self, 
                 min_delay: float = 1.0,
                 max_delay: float = 5.0,
                 decoy_mode: bool = False):
        """
        Initialize stealth scanner
        
        Args:
            min_delay: Minimum delay between packets
            max_delay: Maximum delay between packets
            decoy_mode:  Use decoy scanning (not implemented - requires raw sockets)
        """
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.decoy_mode = decoy_mode
    
    async def scan_port(self, host: str, port: int) -> PortResult:
        """
        Scan single port with stealth techniques
        """
        # Random delay before scan
        delay = random.uniform(self.min_delay, self. max_delay)
        await asyncio.sleep(delay)
        
        # Use SYN scan (stealthier than connect scan)
        result = await syn_scan(host, port)
        
        # Add stealth metadata
        result.extra_info['stealth_delay'] = delay
        result.extra_info['scan_method'] = 'stealth'
        
        return result
    
    async def scan_ports_randomized(self, 
                                      host: str, 
                                      ports: List[int]) -> List[PortResult]: 
        """
        Scan ports in random order with delays
        """
        # Randomize port order
        shuffled_ports = ports. copy()
        random.shuffle(shuffled_ports)
        
        results = []
        for port in shuffled_ports: 
            result = await self.scan_port(host, port)
            results.append(result)
        
        # Sort results back to original order
        results.sort(key=lambda r: r.port)
        
        return results


async def scan(host: str, port: int) -> PortResult:
    """Convenience function for stealth scan"""
    scanner = StealthScanner(min_delay=0.5, max_delay=2.0)
    return await scanner.scan_port(host, port)