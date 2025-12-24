"""
Risk scoring and attack surface analysis
"""

from typing import List, Dict
from enum import Enum

from scanner.core.scanner_engine import PortResult, ScanResult, ScanStatus
from scanner.intelligence.cve_mapper import CVEMapper


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class RiskScorer:
    """Calculate risk scores for scan results"""
    
    # Port risk database
    HIGH_RISK_PORTS = {
        21: 'FTP - Unencrypted file transfer',
        23: 'Telnet - Unencrypted remote access',
        445: 'SMB - Frequent attack vector',
        3389: 'RDP - Remote desktop exposure',
        5900: 'VNC - Remote desktop exposure',
    }
    
    MEDIUM_RISK_PORTS = {
        22: 'SSH - Potential brute-force target',
        3306: 'MySQL - Database exposure',
        5432: 'PostgreSQL - Database exposure',
        6379: 'Redis - Often misconfigured',
        27017: 'MongoDB - Database exposure',
    }
    
    @classmethod
    def score_port(cls, port_result: PortResult) -> Dict:
        """
        Score individual port risk
        
        Returns:
            Dictionary with risk assessment
        """
        if port_result.status != ScanStatus.OPEN:
            return {
                'risk_level': RiskLevel.INFO,
                'score': 0,
                'issues': []
            }
        
        port = port_result.port
        issues = []
        base_score = 1  # Default for open port
        
        # Check high-risk ports
        if port in cls.HIGH_RISK_PORTS:
            risk_level = RiskLevel.HIGH
            base_score = 7
            issues.append(cls.HIGH_RISK_PORTS[port])
        
        # Check medium-risk ports
        elif port in cls.MEDIUM_RISK_PORTS:
            risk_level = RiskLevel. MEDIUM
            base_score = 5
            issues.append(cls. MEDIUM_RISK_PORTS[port])
        
        else:
            risk_level = RiskLevel.LOW
            base_score = 3
        
        # Check for CVEs
        if port_result.service and port_result.version:
            cves = CVEMapper.find_cves(port_result.service, port_result.version)
            
            if cves:
                critical_cves = [c for c in cves if c.severity == 'CRITICAL']
                high_cves = [c for c in cves if c.severity == 'HIGH']
                
                if critical_cves:
                    risk_level = RiskLevel. CRITICAL
                    base_score = 10
                    issues.append(f'{len(critical_cves)} CRITICAL CVE(s) found')
                
                elif high_cves:
                    risk_level = max(risk_level, RiskLevel.HIGH, key=lambda x: x.value)
                    base_score = max(base_score, 8)
                    issues.append(f'{len(high_cves)} HIGH CVE(s) found')
        
        # Check for default credentials indicators
        if port_result.banner:
            banner_lower = port_result.banner.lower()
            if 'default' in banner_lower or 'admin' in banner_lower:
                issues.append('Potential default credentials')
                base_score += 2
        
        return {
            'risk_level':  risk_level,
            'score': min(base_score, 10),  # Cap at 10
            'issues':  issues
        }
    
    @classmethod
    def score_scan_result(cls, scan_result: ScanResult) -> Dict:
        """
        Score entire scan result
        
        Returns: 
            Comprehensive risk assessment
        """
        port_scores = [cls.score_port(p) for p in scan_result. open_ports]
        
        if not port_scores:
            return {
                'overall_risk': RiskLevel.INFO,
                'total_score': 0,
                'attack_surface': 'minimal',
                'critical_issues': [],
                'recommendations': ['No open ports detected']
            }
        
        # Calculate aggregate score
        total_score = sum(s['score'] for s in port_scores)
        avg_score = total_score / len(port_scores)
        
        # Determine overall risk
        max_risk = max(s['risk_level'] for s in port_scores)
        
        # Collect critical issues
        critical_issues = []
        for port, score_data in zip(scan_result.open_ports, port_scores):
            if score_data['risk_level']. value >= RiskLevel.HIGH.value:
                critical_issues.append({
                    'port': port. port,
                    'service':  port.service,
                    'risk':  score_data['risk_level']. name,
                    'issues': score_data['issues']
                })
        
        # Attack surface assessment
        attack_surface = cls._assess_attack_surface(len(scan_result.open_ports))
        
        # Generate recommendations
        recommendations = cls._generate_recommendations(scan_result, port_scores)
        
        return {
            'overall_risk':  max_risk,
            'total_score': total_score,
            'average_score': avg_score,
            'attack_surface': attack_surface,
            'critical_issues': critical_issues,
            'recommendations': recommendations,
            'ports_analyzed': len(scan_result.open_ports)
        }
    
    @staticmethod
    def _assess_attack_surface(open_port_count: int) -> str:
        """Assess attack surface based on open port count"""
        if open_port_count == 0:
            return 'minimal'
        elif open_port_count <= 5:
            return 'small'
        elif open_port_count <= 15:
            return 'moderate'
        elif open_port_count <= 30:
            return 'large'
        else:
            return 'extensive'
    
    @staticmethod
    def _generate_recommendations(scan_result: ScanResult, port_scores: List[Dict]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check for high-risk services
        high_risk_ports = [
            p for p, s in zip(scan_result.open_ports, port_scores)
            if s['risk_level'].value >= RiskLevel.HIGH.value
        ]
        
        if high_risk_ports: 
            recommendations.append('🔴 Close or restrict access to high-risk ports')
        
        # Check for unencrypted services
        unencrypted = [p for p in scan_result.open_ports if p.port in [21, 23, 80]]
        if unencrypted: 
            recommendations.append('🔒 Replace unencrypted services with encrypted alternatives (FTPS, SSH, HTTPS)')
        
        # Check for database exposure
        db_ports = [p for p in scan_result.open_ports if p. port in [3306, 5432, 27017, 6379]]
        if db_ports:
            recommendations.append('🗄️ Restrict database access to localhost or trusted networks only')
        
        # Check for admin interfaces
        admin_ports = [p for p in scan_result.open_ports if p.port in [3389, 5900]]
        if admin_ports:
            recommendations.append('🛡️ Implement VPN or bastion host for administrative access')
        
        # CVE recommendations
        ports_with_cves = [
            p for p in scan_result.open_ports
            if p.service and p.version and CVEMapper.find_cves(p.service, p.version)
        ]
        if ports_with_cves: 
            recommendations.append('⚠️ Update vulnerable services to latest patched versions')
        
        # General recommendations
        if len(scan_result.open_ports) > 10:
            recommendations.append('📊 Audit all open ports and close unnecessary services')
        
        recommendations.append('🔍 Implement intrusion detection/prevention systems (IDS/IPS)')
        recommendations.append('📋 Regular security audits and penetration testing')
        
        return recommendations


def score_port(port_result: PortResult) -> Dict:
    """Convenience function for port risk scoring"""
    return RiskScorer.score_port(port_result)


def score_scan(scan_result: ScanResult) -> Dict:
    """Convenience function for scan risk scoring"""
    return RiskScorer.score_scan_result(scan_result)