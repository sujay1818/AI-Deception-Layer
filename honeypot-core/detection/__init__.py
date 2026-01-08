# detection/__init__.py
from .pipeline import DetectionPipeline
from .api import bp as detection_bp, init_api
from .analytics import leaderboard, ip_summary, severity
from .state import DetectionState, IPState