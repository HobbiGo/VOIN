# Controlled live ABCI restart

CometBFT 1.0.1, single localhost validator.
Original application checkpoint height: 816.
Application restarted with the same checkpoint hash.
Node restarted using existing data and validator identity.
Observed node progress after restart: 817 -> 822.
Observed application height: 822.
Observed saved state height: 822.

This was a graceful restart, not sudden machine failure.
Empty blocks only; transfers and ML-DSA remain disabled in Go.
No genesis reset, key replacement, or production readiness claim.
