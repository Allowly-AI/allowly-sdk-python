# Changelog

## 0.7.0

- Use verifier 5.0.0 and receipt wire 5 only, preserving the original signed
  JWS envelope for verification. This breaking rebuild removes wire-4 parsing.
- Create grants from exact immutable policy editions. Support action choices,
  decision precedence, OR conditions and list operators in the typed policy API.

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
- Require the published PyPI verifier `5.0.0` with a registry-backed lock;
  standalone installs no longer require a sibling verifier checkout.

## 0.6.1

- Accept the runtime's `not_approved` confirmation response while keeping
  legacy `denied_by_user` compatibility. Expose the optional pending resolution
  receipt on both approval and rejection.
- Require `allowly-receipt-format>=4.3.0,<5.0.0` from PyPI for the new
  `confirmation.resolve` event on receipt wire format 4.
