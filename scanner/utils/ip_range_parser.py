"""
IP range and CIDR notation parser with validation
"""

import ipaddress
import re
from typing import List, Iterator
import socket


class IPRangeParser:
    """Parse and validate IP addresses, ranges, and CIDR blocks"""
    
    @staticmethod
    def parse(target: str) -> List[str]:
        """
        Parse various IP input formats: 
        - Single IP: 192.168.1.1
        - CIDR:  192.168.1.0/24
        - Range: 192.168.1.1-192.168.1.50
        - Hostname: example.com
        """
        target = target.strip()
        
        # Hostname
        if IPRangeParser._is_hostname(target):
            try:
                ip = socket.gethostbyname(target)
                return [ip]
            except socket.gaierror:
                raise ValueError(f"Cannot resolve hostname: {target}")
        
        # CIDR notation
        if '/' in target:
            return IPRangeParser._parse_cidr(target)
        
        # IP range
        if '-' in target:
            return IPRangeParser._parse_range(target)
        
        # Single IP
        if IPRangeParser._is_valid_ip(target):
            return [target]
        
        raise ValueError(f"Invalid target format: {target}")
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IPv4 address"""
        try: 
            ipaddress.IPv4Address(ip)
            return True
        except: 
            return False
    
    @staticmethod
    def _is_hostname(target: str) -> bool:
        """Check if target is a hostname"""
        hostname_pattern = re.compile(
            r'^(?! -)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$'
        )
        return bool(hostname_pattern.match(target))
    
    @staticmethod
    def _parse_cidr(cidr: str) -> List[str]:
        """Parse CIDR notation"""
        try: 
            network = ipaddress.IPv4Network(cidr, strict=False)
            # Limit to reasonable size
            if network.num_addresses > 65536:
                raise ValueError("CIDR block too large (max /16)")
            return [str(ip) for ip in network.hosts()]
        except Exception as e:
            raise ValueError(f"Invalid CIDR notation: {cidr} - {e}")
    
    @staticmethod
    def _parse_range(ip_range: str) -> List[str]:
        """Parse IP range (e.g., 192.168.1.1-192.168.1.50)"""
        try:
            start_ip, end_ip = ip_range.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Handle shortened end format
            if '.' not in end_ip:
                base = '. '.join(start_ip.split('.')[:-1])
                end_ip = f"{base}.{end_ip}"
            
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            if start > end:
                raise ValueError("Start IP must be less than end IP")
            
            if int(end) - int(start) > 65536:
                raise ValueError("IP range too large (max 65536 addresses)")
            
            return [str(ipaddress.IPv4Address(ip)) 
                    for ip in range(int(start), int(end) + 1)]
        except Exception as e: 
            raise ValueError(f"Invalid IP range:  {ip_range} - {e}")
    
    @staticmethod
    def validate_target(target: str) -> bool:
        """Validate if target is scannable"""
        try:
            ips = IPRangeParser. parse(target)
            
            # Check for private/reserved ranges
            for ip in ips[: 1]:  # Check first IP
                addr = ipaddress.IPv4Address(ip)
                if addr.is_loopback and ip != "127.0.0.1": 
                    return False
                if addr.is_multicast:
                    return False
                if addr.is_reserved:
                    return False
            
            return True
        except: 
            return False