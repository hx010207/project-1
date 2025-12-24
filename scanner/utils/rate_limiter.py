"""
Adaptive rate limiting to avoid IDS/IPS detection
"""

import asyncio
import time
from typing import Optional
from collections import deque


class RateLimiter: 
    """Token bucket rate limiter with adaptive throttling"""
    
    def __init__(self, 
                 max_rate: int = 1000,
                 time_window: float = 1.0,
                 burst_size: Optional[int] = None):
        """
        Initialize rate limiter
        
        Args:
            max_rate: Maximum operations per time window
            time_window: Time window in seconds
            burst_size: Maximum burst size (defaults to max_rate)
        """
        self.max_rate = max_rate
        self.time_window = time_window
        self.burst_size = burst_size or max_rate
        
        self.tokens = self. burst_size
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()
        
        # Adaptive throttling
        self.recent_errors = deque(maxlen=100)
        self.throttle_factor = 1.0
    
    async def acquire(self, tokens: int = 1):
        """Acquire tokens before operation"""
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            
            # Refill tokens
            self.tokens = min(
                self.burst_size,
                self.tokens + (elapsed * self.max_rate * self.throttle_factor / self.time_window)
            )
            self.last_update = now
            
            # Wait if insufficient tokens
            if self.tokens < tokens:
                wait_time = (tokens - self.tokens) / (self.max_rate * self.throttle_factor / self.time_window)
                await asyncio.sleep(wait_time)
                self.tokens = tokens
            
            self.tokens -= tokens
    
    def report_error(self):
        """Report connection error to trigger throttling"""
        self.recent_errors.append(time.monotonic())
        
        # Calculate error rate
        if len(self. recent_errors) >= 10:
            recent_window = time.monotonic() - 5. 0  # Last 5 seconds
            recent_count = sum(1 for t in self.recent_errors if t > recent_window)
            
            if recent_count > 5:
                # Aggressive throttling
                self.throttle_factor = max(0.1, self.throttle_factor * 0.5)
            elif recent_count > 2:
                # Moderate throttling
                self.throttle_factor = max(0.3, self.throttle_factor * 0.7)
    
    def report_success(self):
        """Report successful operation"""
        # Gradually restore rate
        self.throttle_factor = min(1.0, self.throttle_factor * 1.05)


class TimingProfile:
    """Scan timing profiles (nmap-style)"""
    
    PROFILES = {
        'paranoid': {
            'max_rate': 10,
            'timeout': 300,
            'delay': (5. 0, 10.0),
            'description': 'Extremely slow, evades IDS'
        },
        'sneaky': {
            'max_rate': 50,
            'timeout': 180,
            'delay': (1.0, 3.0),
            'description': 'Slow and stealthy'
        },
        'polite': {
            'max_rate': 200,
            'timeout': 60,
            'delay': (0.4, 0.8),
            'description':  'Reduces load on target'
        },
        'normal': {
            'max_rate': 500,
            'timeout': 30,
            'delay': (0.0, 0.2),
            'description': 'Default balanced speed'
        },
        'aggressive': {
            'max_rate': 1500,
            'timeout': 10,
            'delay': (0.0, 0.05),
            'description': 'Fast, may trigger defenses'
        },
        'insane': {
            'max_rate': 5000,
            'timeout': 5,
            'delay': (0.0, 0.0),
            'description': 'Maximum speed, high risk'
        }
    }
    
    @classmethod
    def get_profile(cls, name: str) -> dict:
        """Get timing profile by name"""
        return cls. PROFILES.get(name.lower(), cls.PROFILES['normal'])
    
    @classmethod
    def list_profiles(cls) -> dict:
        """List all available profiles"""
        return cls.PROFILES