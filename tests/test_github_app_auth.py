"""Unit tests for github_app/auth.py.

Covers: JWT generation, installation token caching, token refresh.
"""

import os
import sys
import time
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from github_app.auth import GitHubAppAuth, JWT_EXPIRY_SECONDS, TOKEN_EXPIRY_MARGIN_SECONDS

def _generate_test_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


TEST_PRIVATE_KEY = _generate_test_key()


class TestJWTGeneration:
    def test_generates_valid_jwt(self):
        auth = GitHubAppAuth(app_id=12345, private_key=TEST_PRIVATE_KEY)
        token = auth.generate_jwt()
        assert isinstance(token, str)
        assert len(token) > 0
        parts = token.split(".")
        assert len(parts) == 3

    def test_jwt_contains_correct_issuer(self):
        import jwt as pyjwt
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        pub_key = load_pem_private_key(
            TEST_PRIVATE_KEY.encode(), password=None
        ).public_key()

        auth = GitHubAppAuth(app_id=99999, private_key=TEST_PRIVATE_KEY)
        token = auth.generate_jwt()
        decoded = pyjwt.decode(token, pub_key, algorithms=["RS256"])
        assert decoded["iss"] == "99999"

    def test_jwt_has_expected_expiry(self):
        import jwt as pyjwt
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        pub_key = load_pem_private_key(
            TEST_PRIVATE_KEY.encode(), password=None
        ).public_key()

        auth = GitHubAppAuth(app_id=12345, private_key=TEST_PRIVATE_KEY)
        token = auth.generate_jwt()
        decoded = pyjwt.decode(token, pub_key, algorithms=["RS256"])
        now = int(time.time())
        assert decoded["exp"] > now
        assert decoded["exp"] <= now + JWT_EXPIRY_SECONDS + 10

    def test_jwt_iat_is_in_past(self):
        import jwt as pyjwt
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        pub_key = load_pem_private_key(
            TEST_PRIVATE_KEY.encode(), password=None
        ).public_key()

        auth = GitHubAppAuth(app_id=12345, private_key=TEST_PRIVATE_KEY)
        token = auth.generate_jwt()
        decoded = pyjwt.decode(token, pub_key, algorithms=["RS256"])
        assert decoded["iat"] <= int(time.time())


class TestInstallationToken:
    @patch("github_app.auth.requests.post")
    def test_fetches_token_from_api(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {
            "token": "ghs_test_token_123",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        auth = GitHubAppAuth(app_id=12345, private_key=TEST_PRIVATE_KEY)
        token = auth.get_installation_token(42)
        assert token == "ghs_test_token_123"
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert "/app/installations/42/access_tokens" in call_url

    @patch("github_app.auth.requests.post")
    def test_caches_token(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "token": "ghs_cached",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        auth = GitHubAppAuth(app_id=12345, private_key=TEST_PRIVATE_KEY)
        token1 = auth.get_installation_token(42)
        token2 = auth.get_installation_token(42)
        assert token1 == token2
        assert mock_post.call_count == 1

    @patch("github_app.auth.requests.post")
    def test_different_installations_get_separate_tokens(self, mock_post):
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.json.return_value = {
                "token": f"ghs_token_{call_count}",
                "expires_at": "2099-01-01T00:00:00Z",
            }
            mock_resp.raise_for_status = MagicMock()
            return mock_resp

        mock_post.side_effect = side_effect

        auth = GitHubAppAuth(app_id=12345, private_key=TEST_PRIVATE_KEY)
        t1 = auth.get_installation_token(1)
        t2 = auth.get_installation_token(2)
        assert t1 != t2
        assert mock_post.call_count == 2

    @patch("github_app.auth.requests.post")
    def test_invalidate_token_forces_refetch(self, mock_post):
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.json.return_value = {
                "token": f"ghs_token_{call_count}",
                "expires_at": "2099-01-01T00:00:00Z",
            }
            mock_resp.raise_for_status = MagicMock()
            return mock_resp

        mock_post.side_effect = side_effect

        auth = GitHubAppAuth(app_id=12345, private_key=TEST_PRIVATE_KEY)
        t1 = auth.get_installation_token(42)
        auth.invalidate_token(42)
        t2 = auth.get_installation_token(42)
        assert t1 != t2
        assert mock_post.call_count == 2

    @patch("github_app.auth.requests.post")
    def test_expired_token_is_refetched(self, mock_post):
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_resp = MagicMock()
            mock_resp.json.return_value = {
                "token": f"ghs_token_{call_count}",
                "expires_at": "2020-01-01T00:00:00Z",
            }
            mock_resp.raise_for_status = MagicMock()
            return mock_resp

        mock_post.side_effect = side_effect

        auth = GitHubAppAuth(app_id=12345, private_key=TEST_PRIVATE_KEY)
        t1 = auth.get_installation_token(42)
        t2 = auth.get_installation_token(42)
        assert mock_post.call_count == 2


class TestFromKeyFile:
    def test_loads_key_from_file(self, tmp_path):
        key_file = tmp_path / "test.pem"
        key_file.write_text(TEST_PRIVATE_KEY)
        auth = GitHubAppAuth.from_key_file(12345, str(key_file))
        token = auth.generate_jwt()
        assert isinstance(token, str)
        assert len(token) > 0
