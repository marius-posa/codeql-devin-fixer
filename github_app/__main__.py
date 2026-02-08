"""Allow running the app via ``python -m github_app``."""

from github_app.main import app, config

app.run(
    host=config.server_host,
    port=config.server_port,
    debug=config.debug,
)
