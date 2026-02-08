"""Entry point for the CodeQL Devin Fixer GitHub App server."""

import pathlib

from dotenv import load_dotenv

from github_app.app import create_app
from github_app.config import AppConfig


def main() -> None:
    env_path = pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)

    config = AppConfig.from_env()
    app = create_app(config)
    app.run(
        host=config.server_host,
        port=config.server_port,
        debug=config.debug,
    )


if __name__ == "__main__":
    main()
