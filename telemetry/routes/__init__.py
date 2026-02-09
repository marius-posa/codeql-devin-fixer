"""Route blueprints for the telemetry Flask application."""

from .api import api_bp
from .orchestrator import orchestrator_bp
from .registry import registry_bp
from .demo import demo_bp

__all__ = ["api_bp", "orchestrator_bp", "registry_bp", "demo_bp"]
