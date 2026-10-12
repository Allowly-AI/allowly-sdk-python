# Policy test vectors

`policy-profile-v1.json` retains every one of the 53 `signature_cases` from
the official receipt-format 5.0.0 policy vectors. It keeps their unchanged
`name`, `definition`, and signed `receipt` fields, which the SDK tests use.
The source's unused replay inputs and tampering cases are not copied.

Source: [profile-v1.json at verifier 5.0.0](https://github.com/Allowly-AI/allowly-receipt-format/blob/e9b092242afdf65dbe6cc4718e25cf67549c0d82/vectors/policy/profile-v1.json).
SHA-256 of that complete source file:
`7955b4c5e8abaa779258fe1ca63383b65c6c7aefe924825b9de94e5ab4a6588d`.

The published Python verifier does not bundle these vectors. Keeping the
test data here lets standalone checkouts run the same cases without a sibling
repository or network fetch at test time. When updating the verifier profile,
refresh this selection from its tagged source and update the provenance here.
