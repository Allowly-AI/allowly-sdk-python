# Changelog

## 0.7.0

- Continue a durable native Execute review using the original operation and
  request. Pending/rejected review never sends; attempted dispatch remains
  recovery-only, including across restart and concurrent calls.
- Add typed, read-only confirmation/escalation `get_status` helpers and
  `readiness`. Monitor responses bind the returned opaque ID; status is not
  execution permission. Preserve the existing `get` methods, status type and
  enum exports, strict lifecycle parsing, and Check's optional confirmation ID.
- Include the existing workspace resolution-webhook setup resource, typed
  events, and strict raw-byte verification helper. Verified callbacks only wake
  saved jobs; they do not grant permission or dispatch a provider request.
- Require verifier `4.3.1` for engine `2026-10-09.1` policy replay on receipt wire `4`.
  Use the published PyPI verifier and a registry-only lock; no sibling-source
  override is needed.

## 0.6.1

- Accept the runtime's `not_approved` confirmation response while keeping
  legacy `denied_by_user` compatibility. Expose the optional pending resolution
  receipt on both approval and rejection.
- Require `allowly-receipt-format>=4.3.0,<5.0.0` from PyPI for the new
  `confirmation.resolve` event on receipt wire format 4.
