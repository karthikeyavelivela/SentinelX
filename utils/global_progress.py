import time
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from utils.timer import scan_timer


class GlobalProgress:
    """Global progress bar controller for SentinelX scans."""

    # Phase weights as percentages (total = 100%)
    PHASE_WEIGHTS = {
        "Phase 1": 5,   # Recon
        "Phase 2": 15,  # Enumeration
        "Phase 3": 40,  # Vulnerability
        "Phase 4": 15,  # Injection
        "Phase 5": 10,  # Misconfiguration
        "Phase 6": 5,   # Risk Scoring
        "Phase 7": 10   # Reporting
    }

    def __init__(self):
        self.progress = None
        self.task = None
        self.current_progress = 0
        self.start_time = None

    def __enter__(self):
        """Initialize and display the global progress bar."""
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]SentinelX Scan"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            refresh_per_second=2
        )
        self.progress.start()
        self.task = self.progress.add_task("Scanning...", total=100)
        self.start_time = time.time()
        scan_timer.start_global()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up the progress bar."""
        if self.progress:
            self.progress.stop()

    def advance(self, phase_name):
        """Advance progress by the weight of the completed phase."""
        if phase_name in self.PHASE_WEIGHTS:
            weight = self.PHASE_WEIGHTS[phase_name]
            self.current_progress += weight
            self.progress.update(self.task, completed=self.current_progress)

    def update_description(self, description):
        """Update the progress bar description."""
        if self.progress and self.task:
            self.progress.update(self.task, description=description)

    def get_eta(self):
        """Calculate estimated time remaining."""
        if self.start_time is None or self.current_progress == 0:
            return "Unknown"

        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return "Calculating..."

        rate = self.current_progress / elapsed
        remaining = (100 - self.current_progress) / rate

        if remaining < 60:
            return f"{int(remaining)}s"
        elif remaining < 3600:
            minutes = int(remaining // 60)
            seconds = int(remaining % 60)
            return f"{minutes}m {seconds}s"
        else:
            hours = int(remaining // 3600)
            minutes = int((remaining % 3600) // 60)
            return f"{hours}h {minutes}m"


# Global progress instance
global_progress = GlobalProgress()
