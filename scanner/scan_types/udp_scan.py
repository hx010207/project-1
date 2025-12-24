"""
UDP port scanning implementation
Detects open/closed UDP ports using ICMP unreachable messages
"""

import asyncio
import socket
import time
from typing import Optional

from scanner. core.scanner_engine import PortResult, ScanStatus


class UDPScanner:
    """UDP port scanner"""
    
    # Protocol-specific UDP probes
    UDP_PROBES = {
        53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS query
        123: b'\x1b' + b'\x00' * 47,  # NTP request
        161: b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63',  # SNMP
        137: b'\x00\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00',  # NetBIOS
    }
    
    @staticmethod
    async def scan_port(host: str, port:  int) -> PortResult:
        """
        Scan UDP port
        
        UDP scanning is unreliable: 
        - Open ports usually don't respond
        - Closed ports send ICMP port unreachable
        - Filtered ports drop packets silently
        """
        start_time = time.monotonic()
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            
            # Send protocol-specific probe or generic payload
            payload = UDPScanner.UDP_PROBES.get(port, b'\x00' * 10)
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                sock.sendto,
                payload,
                (host, port)
            )
            
            # Try to receive response
            try:
                data, addr = await asyncio.wait_for(
                    loop.run_in_executor(None, sock.recvfrom, 1024),
                    timeout=3.0
                )
                
                response_time = time.monotonic() - start_time
                
                # Got response = port is open or service responded
                sock.close()
                
                return PortResult(
                    port=port,
                    status=ScanStatus.OPEN,
                    protocol="udp",
                    response_time=response_time,
                    extra_info={'response_size': len(data)}
                )
            
            except asyncio.TimeoutError:
                # No response = likely open or filtered
                # UDP doesn't reliably indicate open ports
                response_time = time.monotonic() - start_time
                
                sock.close()
                
                return PortResult(
                    port=port,
                    status=ScanStatus.OPEN_FILTERED,  # Ambiguous
                    protocol="udp",
                    response_time=response_time,
                    extra_info={'note': 'No response (open|filtered)'}
                )
        
        except ConnectionRefusedError:
            # ICMP port unreachable = port closed
            response_time = time.monotonic() - start_time
            
            return PortResult(
                port=port,
                status=ScanStatus.CLOSED,
                protocol="udp",
                response_time=response_time
            )
        
        except Exception as e:
            return PortResult(
                port=port,
                status=ScanStatus.UNKNOWN,
                protocol="udp",
                extra_info={'error': str(e)}
            )


# Add OPEN_FILTERED status
ScanStatus.OPEN_FILTERED = "open|filtered"


async def scan(host: str, port: int) -> PortResult:
    """Convenience function for UDP scan"""
    return await UDPScanner.scan_port(host, port)