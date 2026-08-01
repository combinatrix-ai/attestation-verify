#!/usr/bin/env python3
"""Regenerate fixture-derived cargo-fuzz seed corpora.

Run this script from any directory in the repository checkout. It only
rewrites the named seed files below; crash artifacts are left to cargo-fuzz
under ``fuzz/artifacts/``.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
FUZZ = ROOT / "fuzz"


def fixture(relative: str) -> Path:
    return FIXTURES / relative


def load_json(relative: str) -> object:
    return json.loads(fixture(relative).read_text(encoding="utf-8"))


def write_seed(target: str, name: str, data: bytes) -> None:
    path = FUZZ / "corpus" / target / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def decoy_padded_envelope(envelope: str) -> str:
    """Return ``envelope`` with decoy signature lines ahead of the genuine one.

    Each decoy repeats the genuine line's 4-byte key hint, so the key-hint
    filter cannot discard it, and carries the smallest well-formed DER ECDSA
    signature -- ``SEQUENCE { INTEGER 1, INTEGER 1 }``. That is the shape
    that reaches the ECDSA loop at the lowest cost per byte, which is exactly
    the region ``MAX_CHECKPOINT_SIGNATURES`` bounds. A fuzzer is very
    unlikely to synthesise a valid key hint on its own, so seeding it is what
    makes that loop reachable at all.
    """

    body, _, signatures = envelope.partition("\n\n")
    if not signatures:
        raise ValueError("checkpoint envelope has no signature block")
    genuine = next(line for line in signatures.splitlines() if line.startswith("— "))
    key_hint = base64.b64decode(genuine.rsplit(" ", 1)[1], validate=True)[:4]
    decoy = base64.b64encode(key_hint + bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]))
    # One under the limit, so the seed exercises the loop rather than the
    # count check the sibling seeds already cover.
    padding = "".join(f"— decoy {decoy.decode('ascii')}\n" for _ in range(31))
    return f"{body}\n\n{padding}{signatures}"


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Read one definite-length DER TLV and return tag, body, next offset."""

    if offset >= len(data):
        raise ValueError("DER tag is truncated")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("DER length is truncated")
    first_length = data[offset]
    offset += 1
    if first_length & 0x80:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or offset + length_bytes > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset : offset + length_bytes], "big")
        offset += length_bytes
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise ValueError("DER value is truncated")
    return tag, data[offset:end], end


def children(data: bytes) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, body, offset = read_tlv(data, offset)
        result.append((tag, body))
    return result


def extract_sct_list(certificate_der: bytes) -> bytes:
    """Extract the raw TLS SCT list from the leaf certificate extension."""

    certificate_tag, certificate_body, certificate_end = read_tlv(certificate_der)
    if certificate_tag != 0x30 or certificate_end != len(certificate_der):
        raise ValueError("certificate is not a DER sequence")
    certificate_fields = children(certificate_body)
    tbs_tag, tbs_body = certificate_fields[0]
    if tbs_tag != 0x30:
        raise ValueError("certificate has no TBSCertificate sequence")

    extensions_wrapper = next(
        (body for tag, body in children(tbs_body) if tag == 0xA3), None
    )
    if extensions_wrapper is None:
        raise ValueError("certificate has no extensions wrapper")
    extensions_tag, extensions_body, extensions_end = read_tlv(extensions_wrapper)
    if extensions_tag != 0x30 or extensions_end != len(extensions_wrapper):
        raise ValueError("extensions wrapper is not a sequence")

    sct_oid = bytes.fromhex("060a2b06010401d679020402")[2:]
    for extension in children(extensions_body):
        extension_tag, extension_body = extension
        if extension_tag != 0x30:
            continue
        fields = children(extension_body)
        if not fields or fields[0] != (0x06, sct_oid):
            continue
        extn_value = next((body for tag, body in fields[1:] if tag == 0x04), None)
        if extn_value is None:
            raise ValueError("SCT extension has no extnValue")
        inner_tag, inner_body, inner_end = read_tlv(extn_value)
        if inner_tag != 0x04 or inner_end != len(extn_value):
            raise ValueError("SCT extension is not a nested OCTET STRING")
        return inner_body
    raise ValueError("SCT extension not found")


def write_rfc3339_seeds() -> None:
    index = 0
    for relative in ("trusted-roots/public-good.json", "trusted-roots/github.json"):
        root = load_json(relative)

        def visit(value: object) -> None:
            nonlocal index
            if isinstance(value, dict):
                valid_for = value.get("validFor")
                if isinstance(valid_for, dict):
                    for key in ("start", "end"):
                        timestamp = valid_for.get(key)
                        if isinstance(timestamp, str):
                            write_seed("rfc3339", f"fixture-{index:03d}-{key}.txt", timestamp.encode())
                            index += 1
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(root)


def main() -> None:
    golden_relative = "github-cli/tarball-user-slsa-provenance.json"
    tsa_relative = "github-cli/tarball-github-release-tsa.json"
    golden = load_json(golden_relative)
    tsa = load_json(tsa_relative)

    for name, relative in (("golden.json", golden_relative), ("tsa.json", tsa_relative)):
        data = fixture(relative).read_bytes()
        write_seed("bundle", name, data)
        write_seed("statement", name, data)

    write_seed(
        "jsonl",
        "checksums-gh-download.jsonl",
        fixture("github-cli/checksums-gh-download.jsonl").read_bytes(),
    )

    api = load_json("github-cli/attestations-api-response.redacted.json")
    write_seed("github_api", "redacted.json", json_bytes(api))
    inline_api = copy.deepcopy(api)
    attestations = inline_api.get("attestations")
    if not isinstance(attestations, list) or not attestations:
        raise ValueError("API fixture has no attestations")
    attestations[0]["bundle"] = tsa
    write_seed("github_api", "inline-tsa.json", json_bytes(inline_api))

    tlog_entries = golden["verificationMaterial"]["tlogEntries"]
    if not tlog_entries:
        raise ValueError("golden fixture has no Rekor entry")
    tlog_entry = tlog_entries[0]
    write_seed(
        "rekor_body",
        "golden-body.json",
        base64.b64decode(tlog_entry["canonicalizedBody"], validate=True),
    )
    envelope = tlog_entry["inclusionProof"]["checkpoint"]["envelope"]
    write_seed("checkpoint", "golden-envelope.txt", envelope.encode("utf-8"))
    write_seed("checkpoint_verify", "golden-envelope.txt", envelope.encode("utf-8"))
    write_seed(
        "checkpoint_verify",
        "matching-hint-decoys.txt",
        decoy_padded_envelope(envelope).encode("utf-8"),
    )

    certificate_der = base64.b64decode(
        golden["verificationMaterial"]["certificate"]["rawBytes"], validate=True
    )
    write_seed("sct", "golden-list.bin", extract_sct_list(certificate_der))

    for name, relative in (
        ("public-good.json", "trusted-roots/public-good.json"),
        ("github.json", "trusted-roots/github.json"),
    ):
        write_seed("trusted_root", name, fixture(relative).read_bytes())

    write_rfc3339_seeds()


if __name__ == "__main__":
    main()
