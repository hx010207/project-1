"""
Operating system fingerprinting using TCP/IP stack characteristics
"""

import socket
import struct
from typing import Optional, Dict
from dataclasses import dataclass


@dataclass
class OSFingerprint:
    """OS fingerprint result"""
    os_family: str
    os_version: Optional[str] = None
    confidence: str = 'low'
    details: Dict = None


class OSFingerprinter:
    """
    Basic OS fingerprinting using TCP/IP characteristics
    - TTL values
    - Window sizes
    - TCP options
    """
    
    # TTL-based OS signatures
    TTL_SIGNATURES = {
        64: ['Linux', 'Unix', 'MacOS'],
        128: ['Windows'],
        255: ['Solaris', 'AIX', 'Cisco'],
    }
    
    # Window size signatures
    WINDOW_SIGNATURES = {
        8192: 'Windows (older)',
        65535: 'Linux/Unix',
        16384: 'Windows (modern)',
    }
    
    @staticmethod
    def fingerprint_from_ttl(ttl: int) -> OSFingerprint:
        """
        Fingerprint OS based on TTL value
        
        Common TTL values:
        - 64: Linux, Unix, macOS
        - 128: Windows
        - 255: Solaris, AIX, network devices
        """
        # Find closest TTL
        for base_ttl, os_list in OSFingerprinter.TTL_SIGNATURES. items():
            if abs(ttl - base_ttl) <= 10:  # Allow for hop count
                return OSFingerprint(
                    os_family=os_list[0],
                    confidence='medium',
                    details={'ttl': ttl, 'possible_os': os_list}
                )
        
        return OSFingerprint(
            os_family='Unknown',
            confidence='low',
            details={'ttl': ttl}
        )
    
    @staticmethod
    async def fingerprint_tcp_stack(host: str, port: int = 80) -> Optional[OSFingerprint]:
        """
        Perform TCP stack fingerprinting
        
        Note: This is a simplified implementation
        Production tools like nmap use much more sophisticated techniques
        """
        try:
            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5. 0)
            sock.connect((host, port))
            
            # Get peer information (limited without raw sockets)
            # This is a placeholder - real implementation needs raw sockets
            
            sock.close()
            
            # Placeholder:  Would extract TTL, window size, etc.  from raw packets
            return OSFingerprint(
                os_family='Unknown',
                confidence='low',
                details={'note': 'Limited fingerprinting without raw sockets'}
            )
        
        except Exception:
            return None
    
    @staticmethod
    def fingerprint_from_services(open_ports: list) -> OSFingerprint:
        """
        Infer OS from common port combinations
        """
        ports = set(p.port for p in open_ports)
        
        # Windows signatures
        if 3389 in ports or 445 in ports:  # RDP or SMB
            return OSFingerprint(
                os_family='Windows',
                confidence='medium',
                details={'indicators': ['RDP/SMB ports']}
            )
        
        # Linux signatures
        if 22 in ports and 80 in ports:  # SSH + HTTP
            return OSFingerprint(
                os_family='Linux',
                confidence='low',
                details={'indicators': ['SSH + web server']}
            )
        
        return OSFingerprint(
            os_family='Unknown',
            confidence='low'
        )


def fingerprint(host: str, port: int = 80) -> Optional[OSFingerprint]:
    """Convenience function for OS fingerprinting"""
    return OSFingerprinter.fingerprint_from_ttl(64)  # Placeholder