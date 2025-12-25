"""HTTP utilities providing a small requests-based client and errors.

This module provides a `BaseClient` that manages a `requests.Session` with retry/backoff configuration, plus structured exceptions for HTTP and network failures.

The classes and functions here are intended for reuse across small clients that call external HTTP APIs.
"""

import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from helper_functions.logging_config import setup_logger

logger = logger = setup_logger(
    name=os.path.basename(__file__), log_file="that-socs.log"
)


class BaseClient:
    """Small HTTP client that manages a session and retry policy. The client configures a `requests.Session` with an `HTTPAdapter` and `urllib3.util.Retry` when a session is not supplied. It exposes a `request` helper that converts `requests` exceptions into the module's structured errors.

    Args:
        session (requests.Session | None): Optional session to use. If `None` a new session will be created and configured.
        retries (int): Total number of retry attempts (default: 5).
        backoff_factor (float): Backoff factor in seconds between retries (default: 5).
        status_forcelist (tuple): HTTP status codes that should trigger a retry (default: `(429, 500, 502, 503, 504)`).
        allowed_methods (tuple): HTTP methods to retry on.
    """

    def __init__(
        self,
        session: requests.Session | None = None,
        retries: int = 5,
        backoff_factor: float = 5,
        status_forcelist: tuple = (429, 500, 502, 503, 504),
        allowed_methods: tuple = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"),
    ):
        self.session = session or requests.Session()

        # Only configure the adapter when we created the session here.
        if session is None:
            retry = Retry(
                total=retries,
                backoff_factor=backoff_factor,
                status_forcelist=status_forcelist,
                allowed_methods=allowed_methods,
            )

            adapter = HTTPAdapter(max_retries=retry)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Perform an HTTP request and normalize common failures. This wraps `requests.Session.request` and converts common `requests` exceptions into :class:`NetworkError`. Non-2xx responses are raised as :class:`HTTPRequestError`.

        Args:
            method (str): HTTP method (GET, POST, etc.).
            url (str): The URL to request.
            **kwargs: Additional args forwarded to `requests.Session.request` (e.g. `headers`, `params`, `timeout`).

        Returns:
            requests.Response: The successful response object.

        Raises:
            NetworkError: For network-level issues like timeouts or connection errors.
            HTTPRequestError: For completed requests that returned a non-2xx status code.
        """
        try:
            logger.debug("Making HTTP %s request to %s", method, url)
            response = self.session.request(method, url, **kwargs)
        except requests.exceptions.Timeout as exception:
            logger.debug("Timeout on %s %s: %s", method, url, exception)
            raise NetworkError(
                f"Timeout when requesting {url}: {exception}",
                original_exception=exception,
                url=url,
            ) from exception
        except requests.exceptions.ConnectionError as exception:
            logger.debug("ConnectionError on %s %s: %s", method, url, exception)
            raise NetworkError(
                f"Connection error when requesting {url}: {exception}",
                original_exception=exception,
                url=url,
            ) from exception
        except requests.exceptions.RequestException as exception:
            logger.debug("RequestException on %s %s: %s", method, url, exception)
            raise NetworkError(
                f"Request failed for {url}: {exception}",
                original_exception=exception,
                url=url,
            ) from exception

        if not response.ok:
            logger.debug(
                "HTTP %s %s returned status %s", method, url, response.status_code
            )
            raise HTTPRequestError(response=response)

        return response


class HTTPError(Exception):
    """Base class for HTTP-related errors used by this module."""

    pass


class HTTPRequestError(HTTPError):
    """Error raised for HTTP responses with non-2xx status codes.

    Attributes:
        response (requests.Response | None): The original response, if available.
        status_code (int | None): HTTP status code from the response.
        url (str | None): URL of the request that produced the response.
        headers (dict | None): Response headers.
        body (str | None): Response body text where available (may be truncated by :meth:`to_dict`).
    """

    def __init__(
        self, response: requests.Response | None = None, message: str | None = None
    ):
        """Create an :class:`HTTPRequestError`.

        The constructor accepts either ``response`` or an explicit
        ``message``. Callers that only provide the ``response`` may use
        the ``response`` keyword and omit ``message``.

        Args:
            response (requests.Response | None): The HTTP response object.
            message (str | None): Optional custom error message.
        """
        msg = message or (
            f"HTTP {getattr(response, 'status_code', 'error')} for {getattr(response, 'url', '')}"
        )
        super().__init__(msg)
        self.response = response
        self.status_code = getattr(response, "status_code", None)
        self.url = getattr(response, "url", None)
        self.headers = getattr(response, "headers", None)
        try:
            self.body = response.text if response is not None else None
        except Exception:
            self.body = None

    def __str__(self) -> str:
        parts = []
        if self.status_code:
            parts.append(f"HTTP {self.status_code}")
        if self.url:
            parts.append(f"for {self.url}")
        return " ".join(parts) if parts else super().__str__()

    @property
    def is_retryable(self) -> bool:
        if self.status_code is None:
            return False
        return self.status_code == 429 or 500 <= self.status_code < 600

    def to_dict(self) -> dict:
        """Return a serializable representation of the error. The response body is truncated to 200 characters to avoid returning excessively large payloads.

        Returns:
            dict: Keys include `message`, `status_code`, `url`, `headers` and `body`.
        """
        body = self.body
        if isinstance(body, str) and len(body) > 200:
            body = body[:200] + "..."
        return {
            "message": str(self),
            "status_code": self.status_code,
            "url": self.url,
            "headers": dict(self.headers) if self.headers is not None else None,
            "body": body,
        }


class NetworkError(HTTPError):
    """Raised for network-level failures such as timeouts or connection errors. The error wraps the original exception and optionally records the URL that was being requested."""

    def __init__(
        self, message: str, original_exception: BaseException | None, url: str | None
    ):
        """Initialize the NetworkError.

        Args:
            message (str): Error message.
            original_exception (BaseException | None): The original exception raised by the underlying HTTP library.
            url (str | None): The URL that was being requested when the error occurred.
        """
        super().__init__(message)
        self.original_exception = original_exception
        self.url = url

    def __str__(self) -> str:
        base = f"Network error for {self.url}" if self.url else "Network error"
        if self.original_exception:
            return f"{base}: {self.original_exception}"
        return base

    @property
    def is_retryable(self) -> bool:
        """Return True when the underlying error is considered retryable. Currently this treats `requests.exceptions.Timeout` and `requests.exceptions.ConnectionError` as retryable."""
        return isinstance(
            self.original_exception,
            (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
            ),
        )
