"""
TCP SYN scan (stealth scan) implementation
Sends SYN packets without completing handshake - requires raw socket privileges
"""

import asyncio
import socket
import struct
import random
import time
from typing import Optional

from scanner.core.scanner_engine import PortResult, ScanStatus


class TCPSYNScanner:
    """
    TCP SYN (half-open) scan implementation
    Requires root/administrator privileges for raw sockets
    """
    
    def __init__(self):
        self.can_use_raw_sockets = self._check_raw_socket_capability()
    
    @staticmethod
    def _check_raw_socket_capability() -> bool:
        """Check if we have raw socket privileges"""
        try: 
            # Try creating raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.close()
            return True
        except PermissionError:
            return False
        except Exception:
            return False
    
    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """Calculate TCP/IP checksum"""
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        
        return ~checksum & 0xFFFF
    
    @staticmethod
    def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
        """Build TCP SYN packet"""
        
        # IP Header
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 40  # IP header + TCP header
        ip_id = random.randint(1, 65535)
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dst_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                                ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        
        # TCP Header
        tcp_seq = random.randint(0, 2**32 - 1)
        tcp_ack_seq = 0
        tcp_doff = 5
        
        # TCP Flags (SYN)
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        tcp_header = struct.pack('! HHLLBBHHH',
                                 src_port, dst_port, tcp_seq, tcp_ack_seq,
                                 tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
        
        # Pseudo header for checksum
        src_address = socket.inet_aton(src_ip)
        dst_address = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH', src_address, dst_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header
        
        tcp_check = TCPSYNScanner._calculate_checksum(psh)
        
        tcp_header = struct.pack('!HHLLBBH',
                                 src_port, dst_port, tcp_seq, tcp_ack_seq,
                                 tcp_offset_res, tcp_flags, tcp_window) + \
                     struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
        
        return ip_header + tcp_header
    
    async def scan_port(self, host: str, port: int) -> PortResult:
        """
        Perform TCP SYN scan on single port
        Falls back to connect scan if no raw socket privileges
        """
        
        if not self.can_use_raw_sockets:
            # Fallback to TCP Connect scan
            from scanner.scan_types.tcp_connect import scan as tcp_connect_scan
            result = await tcp_connect_scan(host, port)
            result.extra_info['note'] = 'TCP Connect used (no raw socket privileges)'
            return result
        
        start_time = time.monotonic()
        
        try:
            # Get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                src_ip = s.getsockname()[0]
            
            src_port = random.randint(1024, 65535)
            
            # Create raw socket
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            send_sock.setsockopt(socket. IPPROTO_IP, socket. IP_HDRINCL, 1)
            
            recv_sock = socket.socket(socket.AF_INET, socket. SOCK_RAW, socket. IPPROTO_TCP)
            recv_sock.settimeout(2. 0)
            
            # Build and send SYN packet
            packet = self._build_syn_packet(src_ip, host, src_port, port)
            send_sock.sendto(packet, (host, 0))
            
            # Wait for response
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, recv_sock.recv, 1024)
            
            response_time = time.monotonic() - start_time
            
            # Parse response
            if response: 
                # Extract TCP flags
                tcp_header_start = 20  # After IP header
                tcp_flags = response[tcp_header_start + 13]
                
                # SYN-ACK received = port open
                if tcp_flags & 0x12:  # SYN-ACK
                    # Send RST to close connection
                    status = ScanStatus.OPEN
                # RST received = port closed
                elif tcp_flags & 0x04:  # RST
                    status = ScanStatus.CLOSED
                else:
                    status = ScanStatus.UNKNOWN
            else:
                status = ScanStatus.FILTERED
            
            send_sock.close()
            recv_sock.close()
            
            return PortResult(
                port=port,
                status=status,
                protocol="tcp",
                response_time=response_time,
                extra_info={'scan_method': 'SYN'}
            )
        
        except socket.timeout:
            return PortResult(
                port=port,
                status=ScanStatus.FILTERED,
                protocol="tcp"
            )
        
        except Exception as e: 
            # Fallback to connect scan
            from scanner.scan_types.tcp_connect import scan as tcp_connect_scan
            result = await tcp_connect_scan(host, port)
            result.extra_info['syn_scan_error'] = str(e)
            return result


async def scan(host: str, port: int) -> PortResult:
    """Convenience function for TCP SYN scan"""
    scanner = TCPSYNScanner()
    return await scanner.scan_port(host, port)