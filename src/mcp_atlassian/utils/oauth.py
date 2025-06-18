"""OAuth 2.0 utilities for Atlassian Cloud and Data Center authentication.

This module provides utilities for OAuth 2.0 (3LO) authentication with both
Atlassian Cloud and Data Center instances. It handles:
- OAuth configuration for both Cloud and Data Center
- Token acquisition, storage, and refresh
- Session configuration for API clients
"""

import json
import logging
import os
import pprint
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import keyring
import requests

# Configure logging
logger = logging.getLogger("mcp-atlassian.oauth")

# Constants for Cloud OAuth
CLOUD_TOKEN_URL = "https://auth.atlassian.com/oauth/token"  # noqa: S105 - This is a public API endpoint URL, not a password
CLOUD_AUTHORIZE_URL = "https://auth.atlassian.com/authorize"
CLOUD_ID_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

# Constants for Data Center OAuth (endpoints will be constructed with instance URL)
DATACENTER_TOKEN_PATH = "/plugins/servlet/oauth/access-token"  # noqa: S105 - This is a URL path, not a password
DATACENTER_AUTHORIZE_PATH = "/plugins/servlet/oauth/authorize"

# Common constants
TOKEN_EXPIRY_MARGIN = 300  # 5 minutes in seconds
KEYRING_SERVICE_NAME = "mcp-atlassian-oauth"


@dataclass
class OAuthConfig:
    """OAuth 2.0 configuration for Atlassian Cloud and Data Center.

    This class manages the OAuth configuration and tokens for both Cloud and Data Center instances.
    It handles:
    - Authentication configuration (client credentials)
    - Token acquisition and refreshing for both Cloud and Data Center
    - Token storage and retrieval
    - Cloud ID identification (Cloud only)
    - Instance URL configuration (Data Center only)
    """

    client_id: str
    client_secret: str
    redirect_uri: str
    scope: str
    instance_type: str = "cloud"  # "cloud" or "datacenter"
    instance_url: str | None = None  # Required for Data Center, unused for Cloud
    cloud_id: str | None = None  # Required for Cloud, unused for Data Center
    refresh_token: str | None = None
    access_token: str | None = None
    expires_at: float | None = None

    @property
    def is_token_expired(self) -> bool:
        """Check if the access token is expired or will expire soon.

        Returns:
            True if the token is expired or will expire soon, False otherwise.
        """
        # If we don't have a token or expiry time, consider it expired
        if not self.access_token or not self.expires_at:
            return True

        # Consider the token expired if it will expire within the margin
        return time.time() + TOKEN_EXPIRY_MARGIN >= self.expires_at

    @property
    def is_cloud(self) -> bool:
        """Check if this is a Cloud instance configuration.

        Returns:
            True if this is configured for Atlassian Cloud, False for Data Center.
        """
        return self.instance_type == "cloud"

    @property
    def is_datacenter(self) -> bool:
        """Check if this is a Data Center instance configuration.

        Returns:
            True if this is configured for Data Center, False for Cloud.
        """
        return self.instance_type == "datacenter"

    @property
    def token_url(self) -> str:
        """Get the token URL for the configured instance type.

        Returns:
            The appropriate token URL for Cloud or Data Center.
        """
        if self.is_cloud:
            return CLOUD_TOKEN_URL
        else:
            if not self.instance_url:
                raise ValueError("instance_url is required for Data Center OAuth")
            return f"{self.instance_url.rstrip('/')}{DATACENTER_TOKEN_PATH}"

    @property
    def authorize_url_base(self) -> str:
        """Get the base authorization URL for the configured instance type.

        Returns:
            The appropriate authorization URL for Cloud or Data Center.
        """
        if self.is_cloud:
            return CLOUD_AUTHORIZE_URL
        else:
            if not self.instance_url:
                raise ValueError("instance_url is required for Data Center OAuth")
            return f"{self.instance_url.rstrip('/')}{DATACENTER_AUTHORIZE_PATH}"

    def get_authorization_url(self, state: str) -> str:
        """Get the authorization URL for the OAuth 2.0 flow.

        Args:
            state: Random state string for CSRF protection

        Returns:
            The authorization URL to redirect the user to.
        """
        params = {
            "client_id": self.client_id,
            "scope": self.scope,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "state": state,
        }

        # Cloud-specific parameters
        if self.is_cloud:
            params["audience"] = "api.atlassian.com"
            params["prompt"] = "consent"

        return f"{self.authorize_url_base}?{urllib.parse.urlencode(params)}"

    def exchange_code_for_tokens(self, code: str) -> bool:
        """Exchange the authorization code for access and refresh tokens.

        Args:
            code: The authorization code from the callback

        Returns:
            True if tokens were successfully acquired, False otherwise.
        """
        try:
            payload = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": self.redirect_uri,
            }

            logger.info(f"Exchanging authorization code for tokens at {self.token_url}")
            logger.debug(f"Token exchange payload: {pprint.pformat(payload)}")

            response = requests.post(self.token_url, data=payload)

            # Log more details about the response
            logger.debug(f"Token exchange response status: {response.status_code}")
            logger.debug(
                f"Token exchange response headers: {pprint.pformat(response.headers)}"
            )
            logger.debug(f"Token exchange response body: {response.text[:500]}...")

            if not response.ok:
                logger.error(
                    f"Token exchange failed with status {response.status_code}. Response: {response.text}"
                )
                return False

            # Parse the response
            token_data = response.json()

            # Check if required tokens are present
            if "access_token" not in token_data:
                logger.error(
                    f"Access token not found in response. Keys found: {list(token_data.keys())}"
                )
                return False

            if "refresh_token" not in token_data:
                logger.error(
                    "Refresh token not found in response. Ensure 'offline_access' scope is included. "
                    f"Keys found: {list(token_data.keys())}"
                )
                return False

            self.access_token = token_data["access_token"]
            self.refresh_token = token_data["refresh_token"]
            self.expires_at = time.time() + token_data["expires_in"]

            # Get the cloud ID using the access token (Cloud only)
            if self.is_cloud:
                self._get_cloud_id()

            # Save the tokens
            self._save_tokens()

            # Log success message with token details
            logger.info(
                f"✅ OAuth token exchange successful! Access token expires in {token_data['expires_in']}s."
            )
            logger.info(
                f"Access Token (partial): {self.access_token[:10]}...{self.access_token[-5:] if self.access_token else ''}"
            )
            logger.info(
                f"Refresh Token (partial): {self.refresh_token[:5]}...{self.refresh_token[-3:] if self.refresh_token else ''}"
            )

            if self.is_cloud:
                if self.cloud_id:
                    logger.info(f"Cloud ID successfully retrieved: {self.cloud_id}")
                else:
                    logger.warning(
                        "Cloud ID was not retrieved after token exchange. Check accessible resources."
                    )
            else:
                logger.info(f"Data Center OAuth configured for: {self.instance_url}")

            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during token exchange: {e}", exc_info=True)
            return False
        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to decode JSON response from token endpoint: {e}",
                exc_info=True,
            )
            logger.error(
                f"Response text that failed to parse: {response.text if 'response' in locals() else 'Response object not available'}"
            )
            return False
        except Exception as e:
            logger.error(f"Failed to exchange code for tokens: {e}")
            return False

    def refresh_access_token(self) -> bool:
        """Refresh the access token using the refresh token.

        Returns:
            True if the token was successfully refreshed, False otherwise.
        """
        if not self.refresh_token:
            logger.error("No refresh token available")
            return False

        try:
            payload = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
            }

            logger.debug("Refreshing access token...")
            response = requests.post(self.token_url, data=payload)
            response.raise_for_status()

            # Parse the response
            token_data = response.json()
            self.access_token = token_data["access_token"]
            # Refresh token might also be rotated
            if "refresh_token" in token_data:
                self.refresh_token = token_data["refresh_token"]
            self.expires_at = time.time() + token_data["expires_in"]

            # Save the tokens
            self._save_tokens()

            return True
        except Exception as e:
            logger.error(f"Failed to refresh access token: {e}")
            return False

    def ensure_valid_token(self) -> bool:
        """Ensure the access token is valid, refreshing if necessary.

        Returns:
            True if the token is valid (or was refreshed successfully), False otherwise.
        """
        if not self.is_token_expired:
            return True
        return self.refresh_access_token()

    def _get_cloud_id(self) -> None:
        """Get the cloud ID for the Atlassian instance.

        This method queries the accessible resources endpoint to get the cloud ID.
        The cloud ID is needed for API calls with OAuth.
        """
        if not self.access_token:
            logger.debug("No access token available to get cloud ID")
            return

        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            response = requests.get(CLOUD_ID_URL, headers=headers)
            response.raise_for_status()

            resources = response.json()
            if resources and len(resources) > 0:
                # Use the first cloud site (most users have only one)
                # For users with multiple sites, they might need to specify which one to use
                self.cloud_id = resources[0]["id"]
                logger.debug(f"Found cloud ID: {self.cloud_id}")
            else:
                logger.warning("No Atlassian sites found in the response")
        except Exception as e:
            logger.error(f"Failed to get cloud ID: {e}")

    def _get_keyring_username(self) -> str:
        """Get the keyring username for storing tokens.

        The username is based on the client ID to allow multiple OAuth apps.

        Returns:
            A username string for keyring
        """
        return f"oauth-{self.client_id}"

    def _save_tokens(self) -> None:
        """Save the tokens securely using keyring for later use.

        This allows the tokens to be reused between runs without requiring
        the user to go through the authorization flow again.
        """
        try:
            username = self._get_keyring_username()

            # Store token data as JSON string in keyring
            token_data = {
                "refresh_token": self.refresh_token,
                "access_token": self.access_token,
                "expires_at": self.expires_at,
                "cloud_id": self.cloud_id,
                "instance_type": self.instance_type,
                "instance_url": self.instance_url,
            }

            # Store the token data in the system keyring
            keyring.set_password(KEYRING_SERVICE_NAME, username, json.dumps(token_data))

            logger.debug(f"Saved OAuth tokens to keyring for {username}")

            # Also maintain backwards compatibility with file storage
            # for environments where keyring might not work
            self._save_tokens_to_file(token_data)

        except Exception as e:
            logger.error(f"Failed to save tokens to keyring: {e}")
            # Fall back to file storage if keyring fails
            self._save_tokens_to_file()

    def _save_tokens_to_file(self, token_data: dict = None) -> None:
        """Save the tokens to a file as fallback storage.

        Args:
            token_data: Optional dict with token data. If not provided,
                        will use the current object attributes.
        """
        try:
            # Create the directory if it doesn't exist
            token_dir = Path.home() / ".mcp-atlassian"
            token_dir.mkdir(exist_ok=True)

            # Save the tokens to a file
            token_path = token_dir / f"oauth-{self.client_id}.json"

            if token_data is None:
                token_data = {
                    "refresh_token": self.refresh_token,
                    "access_token": self.access_token,
                    "expires_at": self.expires_at,
                    "cloud_id": self.cloud_id,
                    "instance_type": self.instance_type,
                    "instance_url": self.instance_url,
                }

            with open(token_path, "w") as f:
                json.dump(token_data, f)

            logger.debug(f"Saved OAuth tokens to file {token_path} (fallback storage)")
        except Exception as e:
            logger.error(f"Failed to save tokens to file: {e}")

    @staticmethod
    def load_tokens(client_id: str) -> dict[str, Any]:
        """Load tokens securely from keyring.

        Args:
            client_id: The OAuth client ID

        Returns:
            Dict with the token data or empty dict if no tokens found
        """
        username = f"oauth-{client_id}"

        # Try to load tokens from keyring first
        try:
            token_json = keyring.get_password(KEYRING_SERVICE_NAME, username)
            if token_json:
                logger.debug(f"Loaded OAuth tokens from keyring for {username}")
                return json.loads(token_json)
        except Exception as e:
            logger.warning(
                f"Failed to load tokens from keyring: {e}. Trying file fallback."
            )

        # Fall back to loading from file if keyring fails or returns None
        return OAuthConfig._load_tokens_from_file(client_id)

    @staticmethod
    def _load_tokens_from_file(client_id: str) -> dict[str, Any]:
        """Load tokens from a file as fallback.

        Args:
            client_id: The OAuth client ID

        Returns:
            Dict with the token data or empty dict if no tokens found
        """
        token_path = Path.home() / ".mcp-atlassian" / f"oauth-{client_id}.json"

        if not token_path.exists():
            return {}

        try:
            with open(token_path) as f:
                token_data = json.load(f)
                logger.debug(
                    f"Loaded OAuth tokens from file {token_path} (fallback storage)"
                )
                return token_data
        except Exception as e:
            logger.error(f"Failed to load tokens from file: {e}")
            return {}

    @classmethod
    def from_env(cls) -> Optional["OAuthConfig"]:
        """Create an OAuth configuration from environment variables.

        Environment variables:
        - ATLASSIAN_OAUTH_CLIENT_ID: OAuth client ID
        - ATLASSIAN_OAUTH_CLIENT_SECRET: OAuth client secret
        - ATLASSIAN_OAUTH_REDIRECT_URI: OAuth redirect URI
        - ATLASSIAN_OAUTH_SCOPE: OAuth scope
        - ATLASSIAN_OAUTH_INSTANCE_TYPE: "cloud" or "datacenter" (defaults to "cloud")
        - ATLASSIAN_OAUTH_INSTANCE_URL: Instance URL (required for Data Center)
        - ATLASSIAN_OAUTH_CLOUD_ID: Cloud ID (Cloud only, optional)

        Returns:
            OAuthConfig instance or None if required environment variables are missing
        """
        # Check for required environment variables
        client_id = os.getenv("ATLASSIAN_OAUTH_CLIENT_ID")
        client_secret = os.getenv("ATLASSIAN_OAUTH_CLIENT_SECRET")
        redirect_uri = os.getenv("ATLASSIAN_OAUTH_REDIRECT_URI")
        scope = os.getenv("ATLASSIAN_OAUTH_SCOPE")

        # All of these are required for OAuth configuration
        if not all([client_id, client_secret, redirect_uri, scope]):
            return None

        # Determine instance type
        instance_type = os.getenv("ATLASSIAN_OAUTH_INSTANCE_TYPE", "cloud").lower()
        if instance_type not in ["cloud", "datacenter"]:
            logger.warning(
                f"Invalid ATLASSIAN_OAUTH_INSTANCE_TYPE: {instance_type}. Defaulting to 'cloud'."
            )
            instance_type = "cloud"

        # Get instance-specific configuration
        instance_url = os.getenv("ATLASSIAN_OAUTH_INSTANCE_URL")
        cloud_id = os.getenv("ATLASSIAN_OAUTH_CLOUD_ID")

        # Validate instance-specific requirements
        if instance_type == "datacenter" and not instance_url:
            logger.error(
                "ATLASSIAN_OAUTH_INSTANCE_URL is required for Data Center OAuth"
            )
            return None

        # Create the OAuth configuration
        config = cls(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scope=scope,
            instance_type=instance_type,
            instance_url=instance_url,
            cloud_id=cloud_id,
        )

        # Try to load existing tokens
        token_data = cls.load_tokens(client_id)
        if token_data:
            config.refresh_token = token_data.get("refresh_token")
            config.access_token = token_data.get("access_token")
            config.expires_at = token_data.get("expires_at")
            # Load instance-specific data from stored tokens
            if not config.cloud_id and "cloud_id" in token_data:
                config.cloud_id = token_data["cloud_id"]
            if "instance_type" in token_data:
                config.instance_type = token_data["instance_type"]
            if not config.instance_url and "instance_url" in token_data:
                config.instance_url = token_data["instance_url"]

        return config


def configure_oauth_session(
    session: requests.Session, oauth_config: OAuthConfig
) -> bool:
    """Configure a requests session with OAuth 2.0 authentication.

    This function ensures the access token is valid and adds it to the session headers.

    Args:
        session: The requests session to configure
        oauth_config: The OAuth configuration to use

    Returns:
        True if the session was successfully configured, False otherwise
    """
    logger.debug(
        f"configure_oauth_session: Received OAuthConfig with "
        f"access_token_present={bool(oauth_config.access_token)}, "
        f"refresh_token_present={bool(oauth_config.refresh_token)}, "
        f"cloud_id='{oauth_config.cloud_id}'"
    )
    # If user provided only an access token (no refresh_token), use it directly
    if oauth_config.access_token and not oauth_config.refresh_token:
        logger.info(
            "configure_oauth_session: Using provided OAuth access token directly (no refresh_token)."
        )
        session.headers["Authorization"] = f"Bearer {oauth_config.access_token}"
        return True
    logger.debug("configure_oauth_session: Proceeding to ensure_valid_token.")
    # Otherwise, ensure we have a valid token (refresh if needed)
    if not oauth_config.ensure_valid_token():
        logger.error(
            f"configure_oauth_session: ensure_valid_token returned False. "
            f"Token was expired: {oauth_config.is_token_expired}, "
            f"Refresh token present for attempt: {bool(oauth_config.refresh_token)}"
        )
        return False
    session.headers["Authorization"] = f"Bearer {oauth_config.access_token}"
    logger.info("Successfully configured OAuth session for Atlassian Cloud API")
    return True
