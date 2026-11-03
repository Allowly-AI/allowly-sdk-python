import httpx
import pytest

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError

BASE = "https://api.example.com"
GUIDANCE = "# Support agent\nUse ticket.reply with real facts. Policy edition: 2.\n"


async def test_agent_instructions_preserves_text_name_auth_and_json_transport():
    name = "Support /?&=# + café 🧭"
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer runtime-secret"
        assert request.headers["X-Allowly-Edge-Token"] == "edge-secret"
        assert "X-Allowly-Agent-Token" not in request.headers
        if request.url.path == "/readyz":
            return httpx.Response(200, json={"status": "ready"})
        assert request.method == "GET"
        assert request.url.params.multi_items() == [("agent_name", name)]
        assert request.headers["Accept"] == "text/plain"
        assert request.extensions["timeout"]["read"] == 0.25
        return httpx.Response(200, text=GUIDANCE, headers={"Content-Type": "text/plain; charset=utf-8"})

    async with Allowly("runtime-secret", base_url=BASE, timeout=0.25,
                      edge_token="edge-secret") as client:
        client._http._transport = httpx.MockTransport(handler)
        assert await client.agent_instructions(agent_name=name) == GUIDANCE
        assert await client.readiness() is True
    assert len(calls) == 2


@pytest.mark.parametrize("use_supplier", [False, True])
async def test_agent_instructions_rejects_configured_identity_without_downgrade(use_supplier):
    def supplier():
        pytest.fail("identity supplier must not be called")

    config = {"agent_token_supplier": supplier} if use_supplier else {"agent_token": "identity-secret"}
    async with Allowly("runtime-secret", base_url=BASE, **config) as client:
        client._http._transport = httpx.MockTransport(lambda _: pytest.fail("unexpected HTTP"))
        with pytest.raises(ValueError, match="configured agent identity"):
            await client.agent_instructions(agent_name="Support agent")


@pytest.mark.parametrize("name", ["", " ", " padded", "padded ", "a\0b", "a" * 129, None])
async def test_agent_instructions_rejects_invalid_names_before_http(name):
    async with Allowly("runtime-secret", base_url=BASE) as client:
        client._http._transport = httpx.MockTransport(lambda _: pytest.fail("unexpected HTTP"))
        with pytest.raises(ValueError):
            await client.agent_instructions(agent_name=name)


@pytest.mark.parametrize(("status", "mime", "body"), [
    (200, "application/json", b'{"instructions":"text"}'),
    (200, "text/html", b"<html>proxy error</html>"),
    (200, "", b"guidance"),
    (200, "text/plain", b" \n"),
    (200, "text/plain", b'{"error":"proxy error"}'),
    (200, "text/plain", b"<html>proxy error</html>"),
    (200, "text/plain", b"invalid \xff"),
    (200, "text/plain", b"echo runtime-secret"),
    (201, "text/plain", b"guidance"),
    (204, "", b""),
])
async def test_agent_instructions_rejects_invalid_success(status, mime, body):
    async with Allowly("runtime-secret", base_url=BASE, fallback_by_action={"x": "fail_open"}) as client:
        client._http._transport = httpx.MockTransport(lambda _: httpx.Response(status, content=body, headers={"Content-Type": mime}))
        with pytest.raises(AllowlyProtocolError) as error:
            await client.agent_instructions(agent_name="Support agent")
        assert "runtime-secret" not in str(error.value)


@pytest.mark.parametrize("status", [302, 401, 404, 409, 429, 503])
async def test_agent_instructions_retains_api_errors_and_never_redirects_or_falls_back(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers={"Location": "https://other.example/", "Retry-After": "3"},
                              json={"error": {"code": "named_agent_not_found", "message": "runtime-secret invalid",
                                              "fields": [{"field": "agent_name", "message": "exact name required"}]}})

    async with Allowly("runtime-secret", base_url=BASE, fallback_by_action={"x": "fail_open"}) as client:
        client._http._transport = httpx.MockTransport(handler)
        with pytest.raises(AllowlyAPIError) as error:
            await client.agent_instructions(agent_name="Support agent")
        assert error.value.status == status
        assert error.value.code == "named_agent_not_found"
        assert str(error.value) == "[REDACTED] invalid"
        assert error.value.fields[0].field == "agent_name"
        assert error.value.retry_after_seconds == 3
    assert len(calls) == 1


@pytest.mark.parametrize("failure", [httpx.ReadTimeout, httpx.ConnectError])
async def test_agent_instructions_propagates_transport_failures(failure):
    def handler(request):
        raise failure("unavailable", request=request)

    async with Allowly("runtime-secret", base_url=BASE, fallback_by_action={"x": "fail_open"}) as client:
        client._http._transport = httpx.MockTransport(handler)
        with pytest.raises(failure):
            await client.agent_instructions(agent_name="Support agent")
