"""Synthetic JWS fixtures; never used by runtime code."""
from allowly_receipt_format import jws_receipt, jws_signing_input
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def signed_receipt(claims, key=None):
    claims = dict(claims)
    key_id = claims.pop("key_id", "test-key/v1")
    claims.pop("alg", None)
    claims.pop("signature", None)
    payload = {
        "schema_version": "5", "receipt_id": "rcp_test", "workspace_id": "ws_test",
        "issued_at": "2026-04-21T14:32:17.482Z", "decision": "allow",
        "reason": "authorization_granted_action_active", "user_id": "allowly:seal",
        "agent_id": "allowly.seal", "action": "record.seal", "resource": None,
        "context": {}, "authorization_id": "auth_seal", "engine_version": "sha256:" + "a" * 64,
        "policy_ref": {"policy_id": "pol_fixture", "policy_version": 1, "definition_sha256": "b" * 64},
        **claims,
    }
    private_key = key or Ed25519PrivateKey.from_private_bytes(bytes(32))
    return jws_receipt(payload, key_id, private_key.sign(jws_signing_input(payload, key_id)))
