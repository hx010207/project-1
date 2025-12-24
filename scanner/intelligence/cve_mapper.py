"""
CVE (Common Vulnerabilities and Exposures) mapping
Maps detected services to known vulnerabilities
"""

from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class CVERecord:
    """CVE vulnerability record"""
    cve_id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    affected_versions: List[str]
    cvss_score: Optional[float] = None
    published_date: Optional[str] = None


class CVEMapper:
    """
    Map services to CVE database
    
    Note: This is a simplified static database
    Production systems should integrate with: 
    - NVD (National Vulnerability Database)
    - CVE. org API
    - Vulners
    - Shodan
    """
    
    # Static CVE database (subset for demonstration)
    CVE_DATABASE = {
        'OpenSSH': [
            CVERecord(
                cve_id='CVE-2023-38408',
                severity='HIGH',
                description='Remote Code Execution in OpenSSH',
                affected_versions=['7.0', '7.1', '7.2', '7.3', '7.4', '7.5', '7.6', '7.7', '7.8', '7.9'],
                cvss_score=8.1
            ),
            CVERecord(
                cve_id='CVE-2021-41617',
                severity='MEDIUM',
                description='Privilege escalation via supplemental groups',
                affected_versions=['6.2', '6.3', '6.4', '6.5', '6.6', '6.7', '6.8', '6.9', '7.0'],
                cvss_score=7.0
            ),
        ],
        'Apache':  [
            CVERecord(
                cve_id='CVE-2021-44790',
                severity='CRITICAL',
                description='Buffer overflow in mod_lua',
                affected_versions=['2.4.0', '2.4.1', '2.4.2', '2.4.46', '2.4.47', '2.4.48', '2.4.49', '2.4.50'],
                cvss_score=9.8
            ),
            CVERecord(
                cve_id='CVE-2021-42013',
                severity='CRITICAL',
                description='Path traversal and RCE',
                affected_versions=['2.4.49', '2.4.50'],
                cvss_score=9.8
            ),
        ],
        'nginx': [
            CVERecord(
                cve_id='CVE-2021-23017',
                severity='HIGH',
                description='Off-by-one in resolver',
                affected_versions=['0.6.18', '1.20.0'],
                cvss_score=8.1
            ),
        ],
        'MySQL': [
            CVERecord(
                cve_id='CVE-2023-21980',
                severity='HIGH',
                description='Unspecified vulnerability in Server',
                affected_versions=['5.7.41', '8.0.32'],
                cvss_score=7.1
            ),
        ],
        'vsftpd': [
            CVERecord(
                cve_id='CVE-2011-2523',
                severity='CRITICAL',
                description='Backdoor in vsftpd 2.3.4',
                affected_versions=['2.3.4'],
                cvss_score=10.0
            ),
        ],
    }
    
    @classmethod
    def find_cves(cls, service: str, version: Optional[str] = None) -> List[CVERecord]:
        """
        Find CVEs for service and version
        
        Args: 
            service: Service name
            version: Service version (optional)
        
        Returns:
            List of matching CVE records
        """
        cves = cls.CVE_DATABASE.get(service, [])
        
        if not version:
            return cves
        
        # Filter by version
        matching_cves = []
        for cve in cves:
            if cls._version_affected(version, cve.affected_versions):
                matching_cves.append(cve)
        
        return matching_cves
    
    @staticmethod
    def _version_affected(version: str, affected_versions: List[str]) -> bool:
        """Check if version is in affected list"""
        # Simple string matching (production should use semantic versioning)
        version_clean = version.split('-')[0]  # Remove suffixes
        
        for affected in affected_versions: 
            if affected in version_clean or version_clean. startswith(affected):
                return True
        
        return False
    
    @classmethod
    def get_vulnerability_summary(cls, service: str, version: Optional[str] = None) -> Dict:
        """
        Get vulnerability summary statistics
        
        Returns:
            Dictionary with counts by severity
        """
        cves = cls.find_cves(service, version)
        
        summary = {
            'total':  len(cves),
            'critical': sum(1 for c in cves if c.severity == 'CRITICAL'),
            'high': sum(1 for c in cves if c.severity == 'HIGH'),
            'medium': sum(1 for c in cves if c.severity == 'MEDIUM'),
            'low': sum(1 for c in cves if c.severity == 'LOW'),
        }
        
        return summary


def lookup_cves(service: str, version: Optional[str] = None) -> List[CVERecord]:
    """Convenience function for CVE lookup"""
    return CVEMapper.find_cves(service, version)