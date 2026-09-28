import copy
import json

import httpx
import pytest
import respx

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError, CustomExecutableCreateRequest


def response_body():
    return {
        "enabled_executable_id": "exe_custom", "provider_id": "customer-defined-123",
        "provider_name": "Update customer", "category": "customer_defined", "origin": "https://api.example.com",
        "catalog_revision": "customer-defined.v1:sha256:" + "a" * 64, "status": "customer_defined",
        "credential_location": "customer_runtime", "connection_status": "not_verified",
        "allowly_live_tested": False, "tls_witness_tested": False,
        "operations": [{
            "provider_id": "customer-defined-123", "operation_id": "custom.123", "label": "Update customer",
            "method": "PATCH", "path": "/v1/customers/{customer_id}", "effect": "write",
            "request_content_type": "application/json", "required_headers": ["authorization", "content-type"],
            "status": "customer_defined", "definition_fingerprint": "sha256:" + "b" * 64,
            "capabilities": {
                "customer_reported_receipt": {"available": True, "evidence_source": "customer_reported"},
                "tls_witness": {"available": False, "evidence_source": "independent_allowly_witness", "profile": "customer_held_tlsn_bundle_v1", "reason": "online_witness_service_not_configured", "api_request_match_verification": "not_performed"},
            },
            "allowly_live_tested": False, "tls_witness_tested": False,
        }],
        "operation_count": 1, "enabled_at": "2026-09-28T00:00:00Z", "disabled_at": None,
    }


REQUEST = CustomExecutableCreateRequest(
    name="Update customer", url="https://api.example.com/v1/customers/{customer_id}", method="PATCH",
    request_content_type="application/json", required_headers=["authorization"],
)


@respx.mock
async def test_custom_executable_serialization_and_operation_pins():
    route = respx.post("https://api.allowly.ai/v1/setup/custom-executables").mock(return_value=httpx.Response(201, json=response_body()))
    async with Allowly(api_key="setup-key") as client:
        result = await client.create_custom_executable(REQUEST)
    assert json.loads(route.calls[0].request.content) == {
        "name": REQUEST.name, "url": REQUEST.url, "method": "PATCH",
        "request_content_type": "application/json", "required_headers": ["authorization"],
    }
    assert result.enabled_executable_id == "exe_custom"
    assert result.catalog_revision == response_body()["catalog_revision"]
    assert result.operations[0].definition_fingerprint == "sha256:" + "b" * 64
    witness = result.operations[0].capabilities.tls_witness
    assert witness.available is False
    assert witness.evidence_source == "independent_allowly_witness"
    assert witness.api_request_match_verification == "not_performed"
    assert result.status == "customer_defined"
    assert result.connection_status == "not_verified"
    assert result.allowly_live_tested is False
    assert result.tls_witness_tested is False


@pytest.mark.parametrize("override", [
    {"operation_count": 2}, {"operation_count": True}, {"operations": []},
    {"allowly_live_tested": "false"}, {"credential_location": "allowly"},
    {"operations": [{**response_body()["operations"][0], "definition_fingerprint": "invalid"}]},
    {"operations": [{**response_body()["operations"][0], "provider_id": "another-provider"}]},
    {"operations": [{**response_body()["operations"][0], "capabilities": {"tls_witness": {}}}]},
])
@respx.mock
async def test_custom_executable_rejects_malformed_response(override):
    respx.post("https://api.allowly.ai/v1/setup/custom-executables").mock(return_value=httpx.Response(201, json={**response_body(), **copy.deepcopy(override)}))
    async with Allowly(api_key="setup-key") as client:
        with pytest.raises(AllowlyProtocolError):
            await client.create_custom_executable(REQUEST)


@respx.mock
async def test_custom_executable_requires_setup_key_without_fallback_or_retry():
    route = respx.post("https://api.allowly.ai/v1/setup/custom-executables").mock(return_value=httpx.Response(403, json={"error": {"code": "setup_key_required", "message": "Setup key required"}}))
    async with Allowly(api_key="runtime-key") as client:
        with pytest.raises(AllowlyAPIError) as error:
            await client.create_custom_executable(REQUEST)
    assert error.value.code == "setup_key_required"
    assert route.call_count == 1
