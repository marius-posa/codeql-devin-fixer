"""Route blueprints for the telemetry Flask application."""

from routes.api import api_bp
from routes.orchestrator import orchestrator_bp
from routes.registry import registry_bp
from routes.demo import demo_bp

__all__ = ["api_bp", "orchestrator_bp", "registry_bp", "demo_bp"]
