"""
Service and version detection using banner analysis and signatures
"""

import re
from typing import Optional, Tuple, Dict
from dataclasses import dataclass


@dataclass
class ServiceSignature:
    """Service identification signature"""
    name: str
    pattern: str
    version_pattern: Optional[str] = None


class ServiceFingerprinter:
    """Identify services and versions from banners and behaviors"""
    
    # Service signature database
    SIGNATURES = [
        # HTTP Servers
        ServiceSignature('Apache', r'Apache[/\s]([\d.]+)', r'Apache[/\s]([\d.]+)'),
        ServiceSignature('nginx', r'nginx[/\s]([\d.]+)', r'nginx[/\s]([\d.]+)'),
        ServiceSignature('Microsoft-IIS', r'Microsoft-IIS[/\s]([\d.]+)', r'Microsoft-IIS[/\s]([\d.]+)'),
        ServiceSignature('lighttpd', r'lighttpd[/\s]([\d.]+)', r'lighttpd[/\s]([\d.]+)'),
        
        # SSH
        ServiceSignature('OpenSSH', r'OpenSSH[_\s]([\d.]+)', r'OpenSSH[_\s]([\d.]+[p\d]*)'),
        ServiceSignature('Dropbear', r'dropbear[_\s]([\d.]+)', r'dropbear[_\s]([\d.]+)'),
        
        # FTP
        ServiceSignature('ProFTPD', r'ProFTPD ([\d.]+)', r'ProFTPD ([\d.]+[a-z]*)'),
        ServiceSignature('vsftpd', r'vsftpd ([\d.]+)', r'vsftpd ([\d.]+)'),
        ServiceSignature('FileZilla', r'FileZilla Server ([\d.]+)', r'FileZilla Server ([\d. ]+)'),
        
        # Database
        ServiceSignature('MySQL', r'mysql.*?([\d.]+)', r'([\d.]+[\-\w]*)'),
        ServiceSignature('PostgreSQL', r'PostgreSQL ([\d.]+)', r'([\d.]+)'),
        ServiceSignature('MongoDB', r'MongoDB ([\d. ]+)', r'([\d.]+)'),
        ServiceSignature('Redis', r'Redis.*? v=([\d.]+)', r'v=([\d.]+)'),
        
        # Mail
        ServiceSignature('Postfix', r'Postfix', None),
        ServiceSignature('Sendmail', r'Sendmail ([\d.]+)', r'([\d.]+)'),
        ServiceSignature('Exim', r'Exim ([\d.]+)', r'([\d.]+)'),
        
        # Other
        ServiceSignature('Tomcat', r'Apache Tomcat[/\s]([\d.]+)', r'Apache Tomcat[/\s]([\d.]+)'),
        ServiceSignature('Jetty', r'Jetty\(([\d.]+)', r'Jetty\(([\d.]+)'),
        ServiceSignature('RabbitMQ', r'RabbitMQ ([\d. ]+)', r'([\d.]+)'),
    ]
    
    # Well-known port-to-service mapping
    COMMON_PORTS = {
        20: 'ftp-data',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        445: 'smb',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
        5900: 'vnc',
        6379: 'redis',
        8080: 'http-proxy',
        8443: 'https-alt',
        27017: 'mongodb',
    }
    
    @classmethod
    def identify_service(cls, port: int, banner: Optional[str] = None) -> Tuple[str, Optional[str]]:
        """
        Identify service and version
        
        Args:
            port: Port number
            banner: Service banner (if available)
        
        Returns: 
            Tuple of (service_name, version)
        """
        service_name = cls. COMMON_PORTS.get(port, 'unknown')
        version = None
        
        # If banner available, try signature matching
        if banner:
            for signature in cls.SIGNATURES: 
                match = re.search(signature.pattern, banner, re.IGNORECASE)
                if match:
                    service_name = signature.name
                    
                    # Extract version
                    if signature.version_pattern:
                        version_match = re.search(signature. version_pattern, banner, re.IGNORECASE)
                        if version_match: 
                            version = version_match. group(1)
                    
                    break
        
        return service_name, version
    
    @classmethod
    def get_service_info(cls, port: int, banner: Optional[str] = None) -> Dict:
        """
        Get comprehensive service information
        
        Returns:
            Dictionary with service details
        """
        service, version = cls.identify_service(port, banner)
        
        return {
            'service': service,
            'version':  version,
            'banner': banner,
            'confidence': 'high' if banner else 'medium'
        }


def identify(port: int, banner: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """Convenience function for service identification"""
    return ServiceFingerprinter.identify_service(port, banner)