"""
Banner grabbing for service identification
Captures service banners and initial responses
"""

import asyncio
import re
from typing import Optional, Dict

from scanner.core.scanner_engine import PortResult


class BannerGrabber: 
    """Grab service banners from open ports"""
    
    # Protocol-specific probes
    PROBES = {
        21: b'',  # FTP - waits for banner
        22: b'',  # SSH - waits for banner
        23: b'',  # Telnet - waits for banner
        25: b'EHLO scanner\r\n',  # SMTP
        80: b'GET / HTTP/1.1\r\nHost: target\r\n\r\n',  # HTTP
        110: b'',  # POP3 - waits for banner
        143: b'',  # IMAP - waits for banner
        443: b'',  # HTTPS - needs TLS handshake
        3306: b'',  # MySQL - waits for banner
        5432: b'',  # PostgreSQL
        6379: b'PING\r\n',  # Redis
        8080: b'GET / HTTP/1.1\r\nHost: target\r\n\r\n',  # HTTP-Alt
    }
    
    @staticmethod
    async def grab_banner(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
        """
        Attempt to grab banner from service
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
        
        Returns:
            Banner string if successful
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Send protocol-specific probe
            probe = BannerGrabber. PROBES.get(port, b'')
            if probe:
                writer.write(probe)
                await writer.drain()
            
            # Read response
            try:
                banner_bytes = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=3.0
                )
                
                # Decode banner
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                
                writer.close()
                await writer.wait_closed()
                
                return banner if banner else None
            
            except asyncio.TimeoutError:
                writer.close()
                await writer.wait_closed()
                return None
        
        except Exception: 
            return None
    
    @staticmethod
    async def enrich_port_result(host: str, port_result: PortResult) -> PortResult:
        """
        Enrich port result with banner information
        
        Args: 
            host: Target host
            port_result: Original port result
        
        Returns: 
            Enhanced port result with banner
        """
        if port_result.status. value == "open":
            banner = await BannerGrabber.grab_banner(host, port_result.port)
            if banner:
                port_result. banner = banner
        
        return port_result


async def grab(host: str, port: int) -> Optional[str]:
    """Convenience function for banner grabbing"""
    return await BannerGrabber.grab_banner(host, port)