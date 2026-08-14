"""QualityCI deterministic manufacturing-quality regression core."""

from .engine import run_case
from .models import CheckStatus, RunResult

__all__ = ["CheckStatus", "RunResult", "run_case"]
__version__ = "0.2.0.dev0"
