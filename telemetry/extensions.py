"""Shared Flask extensions initialised with the ``init_app`` pattern."""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    default_limits=["120/minute"],
    storage_uri="memory://",
)
