"""Unit tests for helper_functions.http_handler.

These tests validate the error types and the BaseClient request behavior by using lightweight fake sessions and crafted `requests.Response` objects.
"""

import pytest
import requests
from helper_functions.http_handler import (
    BaseClient,
    HTTPRequestError,
    NetworkError,
)


def make_response(status_code=500, url="https://example.com", text="error body"):
    """Create a :class:`requests.Response` with minimal attributes.

    Args:
        status_code (int): HTTP status code to set on the response.
        url (str): URL to assign to the response.
        text (str): Response body text.

    Returns:
        requests.Response: A constructed response object for tests.
    """
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = text.encode("utf-8")
    resp.url = url
    resp.headers = {"Content-Type": "text/plain"}
    return resp


def test_httprequesterror_properties_and_to_dict():
    """Test :class:`HTTPRequestError` properties and :meth:`to_dict` method.

    Creates an :class:`HTTPRequestError` from a crafted :class:`requests.Response` and verifies that the properties and :meth:`to_dict` output are as expected.

    Returns:
        None
    """
    resp = make_response(502, "https://api.test/endpoint", "server error")
    err = HTTPRequestError(response=resp)

    assert err.status_code == 502
    assert "https://api.test/endpoint" in str(err)
    d = err.to_dict()
    assert d["status_code"] == 502
    assert d["url"] == "https://api.test/endpoint"
    assert d["body"] == "server error"
    assert err.is_retryable is True


def test_networkerror_is_retryable_for_timeout():
    """Test :class:`NetworkError` is retryable for timeout exceptions.

    Returns:
        None
    """
    orig = requests.exceptions.Timeout("timed out")
    err = NetworkError("timeout", original_exception=orig, url="https://example.com")
    assert err.is_retryable is True
    assert "Network error" in str(err)


def test_baseclient_request_raises_http_request_error_for_non_ok():
    """Test :class:`BaseClient.request` raises :class:`HTTPRequestError` for non-OK responses.

    Returns:
        None
    """

    class FakeSession:
        def request(self, method, url, **kwargs):
            return make_response(404, url, "not found")

    client = BaseClient(session=FakeSession())
    with pytest.raises(HTTPRequestError) as excinfo:
        client.request("GET", "https://example.com")
    err = excinfo.value
    assert err.status_code == 404
    assert err.url == "https://example.com"


def test_baseclient_request_raises_network_error_for_connection_error():
    """Test :class:`BaseClient.request` raises :class:`NetworkError` for connection errors.

    Returns:
        None
    """

    class FakeSession:
        def request(self, method, url, **kwargs):
            raise requests.exceptions.ConnectionError("conn fail")

    client = BaseClient(session=FakeSession())
    with pytest.raises(NetworkError) as excinfo:
        client.request("GET", "https://example.com")
    err = excinfo.value
    assert isinstance(err.original_exception, requests.exceptions.ConnectionError)
