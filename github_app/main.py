"""Entry point for the CodeQL Devin Fixer GitHub App server."""

import pathlib

from dotenv import load_dotenv

from github_app.app import create_app  # noqa: E402
from github_app.config import AppConfig  # noqa: E402

env_path = pathlib.Path(__file__).parent / ".env"
if env_path.exists():
    load_dotenv(env_path)

config = AppConfig.from_env()
app = create_app(config)

if __name__ == "__main__":
    app.run(
        host=config.server_host,
        port=config.server_port,
        debug=config.debug,
    )
