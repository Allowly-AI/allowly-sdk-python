import copy
import json
from dataclasses import asdict
from pathlib import Path

import httpx
import pytest
import respx

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError
from allowly.policies import validate_policy_definition, parse_policy_reference, parse_policy_evaluation, definition_digest

BASE = "https://api.example.com"
VECTORS = json.loads((Path(__file__).resolve().parents[2] / "allowly-receipt-format/vectors/policy/profile-v1.json").read_text())


def definition():
    return copy.deepcopy(VECTORS["signature_cases"][1]["definition"])


def policy_response(value=None, policy_id="review", version=1):
    value = value or definition()
    return {"policy_ref": {"policy_id": policy_id, "policy_version": version, "definition_sha256": definition_digest(value)},
            "definition": value, "description": None, "created_by": "member:owner", "created_at": "2026-10-10T00:00:00Z", "deleted_at": None}


@pytest.mark.parametrize("case", VECTORS["signature_cases"], ids=lambda case: case["name"])
def test_shared_opa_shapes_are_retained_without_renaming_or_recalculation(case):
    assert validate_policy_definition(case["definition"]) == case["definition"]
    evaluation = parse_policy_evaluation(case["receipt"]["policy_eval"])
    assert asdict(evaluation) == case["receipt"]["policy_eval"]
    assert parse_policy_reference(case["receipt"]["policy_ref"]) == case["receipt"]["policy_ref"]


def invalid_definitions():
    cases = []
    def add(name, edit):
        value = definition()
        edit(value)
        cases.append(pytest.param(value, id=name))
    add("old_constraints", lambda d: d["actions"][0].update(constraints={}))
    add("requires_map", lambda d: d.update(requires_confirm_for=[]))
    add("missing_expiry", lambda d: d.pop("default_expiry_days"))
    add("float_expiry", lambda d: d.update(default_expiry_days=1.0))
    add("bool_expiry", lambda d: d.update(default_expiry_days=True))
    add("nul_agent", lambda d: d.update(agent_id="agent\x00"))
    add("surrogate", lambda d: d.update(agent_id="agent\ud800"))
    add("action_decision_label", lambda d: d["actions"][0]["policy"].update(action="allow"))
    add("action_too_long", lambda d: d["actions"][0]["policy"].update(action="a" * 65))
    add("unknown_basic_key", lambda d: d["actions"][0]["policy"].update(extra=True))
    add("duplicate_action", lambda d: d["actions"].append(copy.deepcopy(d["actions"][0])))
    add("guard_null", lambda d: d["actions"][0]["guards"].update(max_per_day=None))
    add("guard_bool", lambda d: d["actions"][0]["guards"].update(max_per_day=True))
    add("guard_unknown", lambda d: d["actions"][0]["guards"].update(confirmation=True))
    add("guard_duplicate_initiator", lambda d: d["actions"][0]["guards"].update(allowed_initiators=["a", "a"]))
    add("default_bad_target", lambda d: d["actions"][0]["policy"].update(default_decision="allow", default_target="agent_owner"))
    add("confirm_team_target", lambda d: d["actions"][0]["policy"].update(default_decision="confirm", default_target="team:legal"))
    add("escalate_unknown_target", lambda d: d["actions"][0]["policy"].update(default_decision="escalate", default_target="team:legal"))
    add("escalate_empty_member", lambda d: d["actions"][0]["policy"].update(default_decision="escalate", default_target="member: "))
    add("undeclared_field", lambda d: d["actions"][0]["policy"]["rules"][0]["conditions"][0].update(field="absent"))
    add("old_neq_operator", lambda d: d["actions"][0]["policy"]["rules"][0]["conditions"][0].update(op="neq"))
    add("bool_integer", lambda d: d["actions"][0]["policy"]["rules"][0]["conditions"][0].update(value=True))
    add("unsafe_integer", lambda d: d["actions"][0]["policy"]["rules"][0]["conditions"][0].update(value=2**53))
    add("float", lambda d: d["actions"][0]["policy"]["rules"][0]["conditions"][0].update(value=1.5))
    add("exists_string", lambda d: d["actions"][0]["policy"]["rules"][0]["conditions"][0].update(op="exists", value="true"))
    add("membership_scalar", lambda d: d["actions"][0]["policy"]["rules"][0]["conditions"][0].update(op="not_in", value=1))
    add("duplicate_rule", lambda d: d["actions"][0]["policy"]["rules"].append(copy.deepcopy(d["actions"][0]["policy"]["rules"][0])))
    add("empty_conditions", lambda d: d["actions"][0]["policy"]["rules"][0].update(conditions=[]))
    add("unknown_rule_key", lambda d: d["actions"][0]["policy"]["rules"][0].update(priority=1))
    add("rule_review_target", lambda d: d["actions"][0]["policy"]["rules"][0].update(decision="confirm", target="someone"))
    return cases


@pytest.mark.parametrize("value", invalid_definitions())
def test_strict_authoring_rejects_legacy_or_invalid_definitions(value):
    with pytest.raises(AllowlyProtocolError):
        validate_policy_definition(value)


@pytest.mark.parametrize("version", [True, False, 0, -1, 1.0, 2**53, "1", None])
def test_reference_has_a_strict_positive_safe_integer_version(version):
    with pytest.raises(AllowlyProtocolError):
        parse_policy_reference({"policy_id": "review", "policy_version": version, "definition_sha256": "a" * 64})


def test_rule_order_unicode_and_safe_bounds_are_preserved_by_original_canonicalizer():
    value = definition()
    basic = value["actions"][0]["policy"]
    basic["rules"].append({**copy.deepcopy(basic["rules"][0]), "id": "second"})
    basic["fields"]["𐀀"] = "string"
    basic["fields"]["\uff61"] = "string"
    basic["rules"][0]["conditions"][0]["value"] = 2**53 - 1
    normalized = validate_policy_definition(value)
    assert normalized == value and normalized is not value
    assert [rule["id"] for rule in normalized["actions"][0]["policy"]["rules"]] == [basic["rules"][0]["id"], "second"]
    assert definition_digest(normalized) == definition_digest(value)
    value["actions"][0]["guards"]["resource_pattern"] = r"record:\u0000"
    assert validate_policy_definition(value) == value, "literal escaped text is not an actual NUL"


@pytest.mark.parametrize("edit", [
    lambda e: e.update(matched_condition=None), lambda e: e.update(input_sha256="A" * 64),
    lambda e: e["result"].update(status="error"), lambda e: e["result"].update(extra=True),
    lambda e: e["result"].pop("target"), lambda e: e["result"].update(decision="confirm", target="team:legal"),
    lambda e: e["result"].update(decision="allow", target="agent_owner"),
    lambda e: e["result"].update(matched_rule_id=None, evaluated_fields={"risk": 1}),
    lambda e: e["result"].update(evaluated_fields={"risk": 1.5}),
])
def test_provisional_evidence_is_exact_not_an_old_condition_summary(edit):
    value = copy.deepcopy(VECTORS["signature_cases"][1]["receipt"]["policy_eval"])
    edit(value)
    with pytest.raises(AllowlyProtocolError):
        parse_policy_evaluation(value)


def test_exists_evidence_keeps_arbitrary_canonical_json_without_a_scalar_only_translator():
    value = copy.deepcopy(VECTORS["signature_cases"][1]["receipt"]["policy_eval"])
    value["result"]["evaluated_fields"] = {"value": {"present": [None, True, 0, "nested"]}}
    assert asdict(parse_policy_evaluation(value)) == value


@respx.mock
@pytest.mark.asyncio
async def test_setup_resource_round_trip_create_get_list_archive_and_provisional_preview():
    retained = definition()
    response = policy_response(retained)
    action = retained["actions"][0]["policy"]["action"]
    evaluation = VECTORS["signature_cases"][1]["receipt"]["policy_eval"]
    create = respx.post(BASE + "/v1/policies").mock(return_value=httpx.Response(201, json=response))
    get = respx.get(BASE + "/v1/policies/review").mock(return_value=httpx.Response(200, json=response))
    listing = respx.get(BASE + "/v1/policies").mock(return_value=httpx.Response(200, json={"items": [response], "has_more": False, "next_cursor": None}))
    preview = respx.post(BASE + "/v1/setup/policies/preview").mock(return_value=httpx.Response(200, json={"provisional": True, "definition_sha256": definition_digest(retained), "action": action, "policy_eval": evaluation}))
    archive = respx.delete(BASE + "/v1/policies/review").mock(return_value=httpx.Response(204))
    async with Allowly("setup-key", base_url=BASE, agent_token_supplier=lambda: (_ for _ in ()).throw(AssertionError("setup never signs agent identity"))) as client:
        created = await client.policies.create(policy_id="review", definition=retained, idempotency_key="create-1")
        assert created.definition == retained and created.policy_ref == response["policy_ref"]
        assert (await client.policies.get("review")).definition == retained
        assert (await client.policies.list(limit=2, cursor="a/b?")).items[0].definition == retained
        result = await client.policies.preview(definition=retained, action=action, context={"risk": 2})
        assert result.provisional is True and asdict(result.policy_eval) == evaluation
        await client.policies.archive("review", idempotency_key="archive-1")
    assert json.loads(create.calls[0].request.content) == {**retained, "policy_id": "review"}
    assert json.loads(preview.calls[0].request.content) == {"definition": retained, "action": action, "context": {"risk": 2}}
    assert dict(listing.calls[0].request.url.params) == {"limit": "2", "cursor": "a/b?"}
    assert archive.calls[0].request.headers["idempotency-key"] == "archive-1"
    for route in (create, get, listing, preview, archive):
        assert route.calls[0].request.headers["authorization"] == "Bearer setup-key"
        assert "x-allowly-agent-token" not in route.calls[0].request.headers


@respx.mock
@pytest.mark.asyncio
async def test_publish_names_previous_exact_edition_and_preserves_receipt_witness_grants():
    value = definition()
    reference = policy_response(value)["policy_ref"]
    previous = {**reference, "policy_version": 1}
    published = {**reference, "policy_version": 2}
    route = respx.post(BASE + "/v1/setup/policies/publish").mock(return_value=httpx.Response(201, json={
        "policy_ref": published, "agent_id": value["agent_id"], "created_by": "member:owner", "created_at": "2026-10-10T00:00:00Z",
        "authorization_migrations": [], "archived_policy_ids": [], "revoked_confirmation_count": 0,
    }))
    async with Allowly("setup-key", base_url=BASE) as client:
        result = await client.policies.publish(policy_id="review", definition=value, previous_policy_ref=previous, idempotency_key="publish-2")
    assert result.policy_ref == published
    assert json.loads(route.calls[0].request.content) == {**value, "policy_id": "review", "previous_policy_ref": previous}
    assert route.calls[0].request.headers["idempotency-key"] == "publish-2"


@pytest.mark.parametrize("changed", ["provisional", "action", "definition_sha256"])
@respx.mock
@pytest.mark.asyncio
async def test_preview_rejects_a_response_for_another_request(changed):
    value = definition()
    action = value["actions"][0]["policy"]["action"]
    response = {"provisional": True, "action": action, "definition_sha256": definition_digest(value), "policy_eval": VECTORS["signature_cases"][1]["receipt"]["policy_eval"]}
    response[changed] = False if changed == "provisional" else "other"
    respx.post(BASE + "/v1/setup/policies/preview").mock(return_value=httpx.Response(200, json=response))
    async with Allowly("setup-key", base_url=BASE) as client:
        with pytest.raises(AllowlyProtocolError):
            await client.policies.preview(definition=value, action=action, context={})


@respx.mock
@pytest.mark.asyncio
async def test_preview_binds_input_commitment_without_recalculating_opa_rules():
    value = definition()
    action = value["actions"][0]["policy"]["action"]
    respx.post(BASE + "/v1/setup/policies/preview").mock(return_value=httpx.Response(200, json={
        "provisional": True, "action": action, "definition_sha256": definition_digest(value),
        "policy_eval": VECTORS["signature_cases"][1]["receipt"]["policy_eval"],
    }))
    async with Allowly("setup-key", base_url=BASE) as client:
        with pytest.raises(AllowlyProtocolError, match="input commitment"):
            await client.policies.preview(definition=value, action=action, context={"risk": 1})


@pytest.mark.parametrize("status,code", [(403, "setup_key_required"), (503, "policy_evaluator_unavailable"), (422, "policy_input_invalid")])
@respx.mock
@pytest.mark.asyncio
async def test_policy_setup_errors_never_retry_or_use_check_fallback(status, code):
    route = respx.post(BASE + "/v1/setup/policies/preview").mock(return_value=httpx.Response(status, json={"error": {"code": code, "message": "not available"}}))
    value = definition()
    async with Allowly("runtime-key", base_url=BASE, fallback_by_action={value["actions"][0]["policy"]["action"]: "fail_open"}) as client:
        with pytest.raises(AllowlyAPIError) as error:
            await client.policies.preview(definition=value, action=value["actions"][0]["policy"]["action"], context={})
    assert error.value.code == code and route.call_count == 1


@pytest.mark.parametrize("engine", ["2026-04-19.1", "a" * 64, "sha256:" + "A" * 64, "sha256:" + "a" * 63, "", None])
@respx.mock
@pytest.mark.asyncio
async def test_check_rejects_old_or_malformed_engine_identity_without_fallback(engine):
    respx.post(BASE + "/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1", "engine_version": engine,
        "results": {"web.search": {"decision": "allow", "reason": "authorization_granted_action_active", "receipt": None}},
    }))
    async with Allowly("runtime-key", base_url=BASE, fallback_by_action={"web.search": "fail_open"}) as client:
        with pytest.raises(AllowlyProtocolError):
            await client.check(authorization_id="auth_1", actions=["web.search"])


@pytest.mark.parametrize("evaluation", [
    {"matched_condition": None, "decision": "allow", "evaluated_fields": {}},
    {"input_sha256": "a" * 64},
    {"input_sha256": "a" * 64, "result": {"profile": "allowly.basic.v1", "status": "ok", "decision": "allow", "target": None, "matched_rule_id": None, "evaluated_fields": {"risk": 1}}},
])
@respx.mock
@pytest.mark.asyncio
async def test_check_rejects_malformed_opa_evidence_without_unsigned_fallback(evaluation):
    respx.post(BASE + "/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1", "engine_version": "sha256:" + "a" * 64,
        "results": {"web.search": {"decision": "allow", "reason": "authorization_granted_action_active", "receipt": None, "policy_eval": evaluation}},
    }))
    async with Allowly("runtime-key", base_url=BASE, fallback_by_action={"web.search": "fail_open"}) as client:
        with pytest.raises(AllowlyProtocolError):
            await client.check(authorization_id="auth_1", actions=["web.search"])


@respx.mock
@pytest.mark.asyncio
async def test_create_binds_response_to_sent_snapshot_when_caller_changes_definition():
    value = definition()
    original = copy.deepcopy(value)
    def during_request(request):
        value["actions"][0]["policy"]["default_decision"] = "allow"
        return httpx.Response(201, json=policy_response(original))
    respx.post(BASE + "/v1/policies").mock(side_effect=during_request)
    async with Allowly("setup-key", base_url=BASE) as client:
        assert (await client.policies.create(policy_id="review", definition=value)).definition == original
