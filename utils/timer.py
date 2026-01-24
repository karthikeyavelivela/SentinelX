import time
from collections import defaultdict


class ScanTimer:
    """High-precision timer for tracking scan execution times."""

    def __init__(self):
        self.start_time = None
        self.phase_times = defaultdict(float)
        self.current_phase = None
        self.phase_start_times = {}

    def start_global(self):
        """Start the global scan timer."""
        self.start_time = time.perf_counter()

    def stop_global(self):
        """Stop the global scan timer and return total elapsed time."""
        if self.start_time is None:
            return 0.0
        return time.perf_counter() - self.start_time

    def start_phase(self, phase_name):
        """Start timing a specific phase."""
        self.current_phase = phase_name
        self.phase_start_times[phase_name] = time.perf_counter()

    def stop_phase(self, phase_name):
        """Stop timing a specific phase and record the duration."""
        if phase_name in self.phase_start_times:
            duration = time.perf_counter() - self.phase_start_times[phase_name]
            self.phase_times[phase_name] = duration
            return duration
        return 0.0

    def get_phase_time(self, phase_name):
        """Get the recorded time for a specific phase."""
        return self.phase_times.get(phase_name, 0.0)

    def get_elapsed_time(self):
        """Get current elapsed time since global start."""
        if self.start_time is None:
            return 0.0
        return time.perf_counter() - self.start_time

    def format_duration(self, seconds):
        """Format seconds into human-readable duration string."""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            secs = int(seconds % 60)
            return f"{hours}h {minutes}m {secs}s"


# Global timer instance
scan_timer = ScanTimer()
