`management-bootstrap-v1.json` is the synthetic, byte-identical controller/API
bootstrap contract fixture. Its all-zero token is public test material only and
must never be staged in an installation. Management provisioning uses OS-random
per-VM tokens, a protected control-plane Secret namespace and a shared issuance
ledger; this fixture confers no deployed trust.
