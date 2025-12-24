"""
Adaptive timeout management
"""

import asyncio
from typing import Optional
from collections import defaultdict


class TimeoutHandler:
    """Adaptive timeout manager with per-host learning"""
    
    def __init__(self, base_timeout: float = 5.0):
        self.base_timeout = base_timeout
        self.host_timeouts = defaultdict(lambda: base_timeout)
        self.host_rtts = defaultdict(list)
    
    def get_timeout(self, host: str, port: Optional[int] = None) -> float:
        """Get adaptive timeout for host"""
        key = f"{host}:{port}" if port else host
        return self.host_timeouts[key]
    
    def record_rtt(self, host: str, rtt: float, port: Optional[int] = None):
        """Record round-trip time for adaptive learning"""
        key = f"{host}:{port}" if port else host
        
        # Keep last 10 RTTs
        self.host_rtts[key]. append(rtt)
        if len(self.host_rtts[key]) > 10:
            self.host_rtts[key].pop(0)
        
        # Calculate adaptive timeout (mean + 2*stddev)
        rtts = self.host_rtts[key]
        if len(rtts) >= 3:
            mean_rtt = sum(rtts) / len(rtts)
            variance = sum((x - mean_rtt) ** 2 for x in rtts) / len(rtts)
            stddev = variance ** 0.5
            
            adaptive_timeout = mean_rtt + (2 * stddev)
            self.host_timeouts[key] = max(
                1.0,  # Minimum timeout
                min(adaptive_timeout, self.base_timeout * 3)  # Maximum timeout
            )
    
    async def with_timeout(self, coro, host: str, port: Optional[int] = None):
        """Execute coroutine with adaptive timeout"""
        timeout = self.get_timeout(host, port)
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            # Increase timeout for this host
            key = f"{host}:{port}" if port else host
            self. host_timeouts[key] = min(
                self.host_timeouts[key] * 1.5,
                self.base_timeout * 3
            )
            raise