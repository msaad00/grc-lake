"""Fuzz inbound webhook signature checks: Stripe billing and GRC Lake receivers.

The ``Stripe-Signature`` header reaches ``verify_stripe_signature`` before any
authentication, so a malformed header must be a clean rejection.

Invariants:
* Verification never raises; it returns a bool for any header, signature,
  timestamp, payload, or secret.
* Soundness: a True result means some ``v1`` entry equals the HMAC-SHA256 of
  ``t.payload`` under one configured secret, with ``t`` inside the tolerance.
* Completeness: a correctly signed header or signature always verifies, and
  stops verifying once the payload changes.
"""

from __future__ import annotations

import hashlib
import hmac

from _input import Input, run

from security_lakehouse.commercial.billing import SIGNATURE_TOLERANCE_SECONDS, verify_stripe_signature
from security_lakehouse.webhook_delivery import (
    sign_payload,
    sign_timestamped_payload,
    verify_signature,
    verify_timestamped_signature,
)

NOW = 1_800_000_000


def _stripe_hmac(secret: str, timestamp: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), timestamp.encode() + b"." + payload, hashlib.sha256).hexdigest()


def _config_secret(inp: Input) -> str:
    # Secrets are operator configuration, not attacker input: keep them encodable.
    return inp.take_text(8).encode("utf-8", "replace").decode("utf-8")


def _check_stripe(inp: Input) -> None:
    secrets = [_config_secret(inp) or "whsec" for _ in range(1 + inp.take_int(2))]
    payload = inp.take_bytes(64)
    header = inp.take_text(96)
    verified = verify_stripe_signature(payload, header, secrets, now=NOW)
    assert isinstance(verified, bool)
    if verified:
        parts = [part.strip().partition("=") for part in header.split(",")]
        timestamp = next(value for key, _, value in reversed(parts) if key == "t")
        assert abs(NOW - int(timestamp)) <= SIGNATURE_TOLERANCE_SECONDS
        expected = {_stripe_hmac(secret, timestamp, payload) for secret in secrets}
        assert any(key == "v1" and value in expected for key, _, value in parts), "unsigned header verified"

    secret = secrets[inp.take_int(len(secrets))]
    sent_at = str(NOW + inp.take_int(2 * SIGNATURE_TOLERANCE_SECONDS + 1) - SIGNATURE_TOLERANCE_SECONDS)
    valid = f"t={sent_at},v1={_stripe_hmac(secret, sent_at, payload)}"
    assert verify_stripe_signature(payload, valid, secrets, now=NOW), "correct Stripe signature rejected"
    assert not verify_stripe_signature(payload + b"x", valid, secrets, now=NOW), "tampered payload verified"


def _check_receiver(inp: Input) -> None:
    secret = _config_secret(inp)
    body = inp.take_bytes(64)
    signature = inp.take_text(80)
    timestamp = inp.take_text(16)
    for verified in (
        verify_signature(secret, body, signature),
        verify_timestamped_signature(secret, body, timestamp, signature, now=NOW),
    ):
        assert isinstance(verified, bool)
    assert verify_signature(secret, body, sign_payload(secret, body))
    assert not verify_signature(secret, body + b"x", sign_payload(secret, body))
    sent_at = NOW - inp.take_int(300)
    signed = sign_timestamped_payload(secret, sent_at, body)
    assert verify_timestamped_signature(secret, body, str(sent_at), signed, now=NOW)
    assert not verify_timestamped_signature(secret, body + b"x", str(sent_at), signed, now=NOW)


def TestOneInput(data: bytes) -> None:
    inp = Input(data)
    if inp.take_int(2):
        _check_stripe(inp)
    else:
        _check_receiver(inp)


if __name__ == "__main__":
    run(TestOneInput)
