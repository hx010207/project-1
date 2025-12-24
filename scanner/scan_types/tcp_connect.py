"""
TCP Connect scan implementation
Full three-way handshake - most reliable but most detectable
"""

import asyncio
import socket
import time
from typing import Optional

from scanner.core.scanner_engine import PortResult, ScanStatus


class TCPConnectScanner:
    """TCP Connect scan using full three-way handshake"""
    
    @staticmethod
    async def scan_port(host: str, port: int) -> PortResult:
        """
        Perform TCP connect scan on single port
        
        Args: 
            host: Target IP/hostname
            port: Target port
        
        Returns:
            PortResult with scan findings
        """
        start_time = time.monotonic()
        
        try: 
            # Attempt connection
            reader, writer = await asyncio.open_connection(host, port)
            
            response_time = time.monotonic() - start_time
            
            # Connection successful - port is open
            writer.close()
            await writer.wait_closed()
            
            return PortResult(
                port=port,
                status=ScanStatus.OPEN,
                protocol="tcp",
                response_time=response_time
            )
        
        except (ConnectionRefusedError, OSError) as e:
            # Connection refused - port is closed
            response_time = time.monotonic() - start_time
            
            # Differentiate between closed and filtered
            if isinstance(e, ConnectionRefusedError):
                status = ScanStatus.CLOSED
            else:
                status = ScanStatus.FILTERED
            
            return PortResult(
                port=port,
                status=status,
                protocol="tcp",
                response_time=response_time
            )
        
        except asyncio.TimeoutError:
            # Timeout - likely filtered by firewall
            return PortResult(
                port=port,
                status=ScanStatus. FILTERED,
                protocol="tcp"
            )
        
        except Exception as e:
            # Unknown error
            return PortResult(
                port=port,
                status=ScanStatus.UNKNOWN,
                protocol="tcp",
                extra_info={'error': str(e)}
            )


async def scan(host: str, port: int) -> PortResult:
    """Convenience function for TCP connect scan"""
    return await TCPConnectScanner.scan_port(host, port)