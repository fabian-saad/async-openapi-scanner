import httpx
from main import check_headers, check_cors, HEADERS


def test_header_check_missing():
    response = httpx.Response(200, headers={})
    score, details = check_headers(response.headers)

    assert score == f"0/{len(HEADERS)}"


def test_cors_check_missing():
    response = httpx.Response(200, headers={})
    vulnerable, details = check_cors(response.headers)

    assert vulnerable is False


def test_header_check_secure():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "X-XSS-Protection": "0"
    }

    response = httpx.Response(200, headers=headers)
    score, details = check_headers(response.headers)

    assert score == f"7/{len(HEADERS)}"


def test_cors_check_secure():
    response = httpx.Response(
        200,
        headers={"access-control-allow-origin": "https://example.com"}
    )

    vulnerable, details = check_cors(response.headers)

    assert vulnerable is False


def test_cors_check_vulnerable():
    response = httpx.Response(
        200,
        headers={"access-control-allow-origin": "*"}
    )

    vulnerable, details = check_cors(response.headers)

    assert vulnerable is True
    assert "Wildcard" in details