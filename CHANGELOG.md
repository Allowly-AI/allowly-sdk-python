# Changelog

## Unreleased

- Accept the runtime's `not_approved` confirmation response while keeping
  legacy `denied_by_user` compatibility. Expose the optional pending resolution
  receipt on both approval and rejection.
- Require verifier 4.3.0 for the new `confirmation.resolve` event. SDK package
  version stays 0.6.0 on this feature branch; the next SDK release will include
  this response support after the verifier release gate is complete.
