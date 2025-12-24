"""
Dynamic concurrency management with resource monitoring
"""

import asyncio
import psutil
from typing import Optional


class ConcurrencyManager: 
    """Manages concurrent scanning operations with dynamic scaling"""
    
    def __init__(self, 
                 max_workers: int = 1000,
                 min_workers:  int = 50,
                 auto_scale: bool = True):
        """
        Initialize concurrency manager
        
        Args:
            max_workers: Maximum concurrent operations
            min_workers: Minimum concurrent operations
            auto_scale: Enable dynamic scaling based on resources
        """
        self.max_workers = max_workers
        self.min_workers = min_workers
        self.auto_scale = auto_scale
        
        self.semaphore = asyncio.Semaphore(max_workers)
        self.active_tasks = 0
        self.completed_tasks = 0
        
        # Resource monitoring
        self._last_scale_check = 0
        self._scale_interval = 5.0  # Check every 5 seconds
    
    async def acquire(self):
        """Acquire worker slot"""
        await self.semaphore.acquire()
        self.active_tasks += 1
        
        # Periodic scaling check
        if self.auto_scale:
            await self._check_and_scale()
    
    def release(self):
        """Release worker slot"""
        self.semaphore.release()
        self.active_tasks -= 1
        self.completed_tasks += 1
    
    async def _check_and_scale(self):
        """Check system resources and adjust concurrency"""
        import time
        now = time.monotonic()
        
        if now - self._last_scale_check < self._scale_interval:
            return
        
        self._last_scale_check = now
        
        # Check CPU and memory
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_percent = psutil.virtual_memory().percent
        
        current_limit = self.semaphore._value + self.active_tasks
        
        # Scale down if resources high
        if cpu_percent > 90 or memory_percent > 85:
            new_limit = max(self.min_workers, int(current_limit * 0.7))
        # Scale up if resources available
        elif cpu_percent < 60 and memory_percent < 70:
            new_limit = min(self.max_workers, int(current_limit * 1.3))
        else:
            return
        
        # Adjust semaphore
        diff = new_limit - current_limit
        if diff > 0:
            for _ in range(diff):
                self.semaphore.release()
        # Cannot easily reduce semaphore, will naturally limit
    
    def get_stats(self) -> dict:
        """Get concurrency statistics"""
        return {
            'active':  self.active_tasks,
            'completed': self.completed_tasks,
            'max_workers':  self.max_workers
        }