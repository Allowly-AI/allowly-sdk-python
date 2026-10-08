# Changelog

## 0.6.1

- Accept the runtime's `not_approved` confirmation response while keeping
  legacy `denied_by_user` compatibility. Expose the optional pending resolution
  receipt on both approval and rejection.
- Require `allowly-receipt-format>=4.3.0,<5.0.0` from PyPI for the new
  `confirmation.resolve` event on receipt wire format 4.
