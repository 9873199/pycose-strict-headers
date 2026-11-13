"""
Tests for the strict COSE_Sign1 decoder (Sign1Message.decode_strict).

All malicious/malformed samples are assembled by byte splicing; the maps with
duplicate keys are never passed through a Python dict, which would collapse them.
"""
import cbor2
import pytest

from pycose import headers
from pycose.exceptions import CoseException, CoseMalformedMessage
from pycose.keys import OKPKey
from pycose.messages.sign1message import Sign1Message


def bstr(data: bytes) -> bytes:
    """Encode bytes as a definite-length CBOR byte string."""
    n = len(data)
    if n < 24:
        return bytes([0x40 + n]) + data
    if n < 256:
        return b'\x58' + bytes([n]) + data
    if n < 65536:
        return b'\x59' + n.to_bytes(2, 'big') + data
    return b'\x5a' + n.to_bytes(4, 'big') + data


def sign1_bytes(phdr_raw: bytes, uhdr_raw: bytes, payload_item: bytes, sig_item: bytes,
                tagged: bool = True) -> bytes:
    """Assemble a COSE_Sign1 message from raw CBOR fragments."""
    return (b'\xd2' if tagged else b'') + b'\x84' + bstr(phdr_raw) + uhdr_raw + payload_item + sig_item


# protected bucket with non-deterministic but legal encoding:
# - map keys out of canonical order (extension label 1000 before label 1)
# - label 1000 encoded as a 4-byte uint instead of the shortest 2-byte form
# {1000: "ext", 1: -8 (EdDSA)}
PHDR_NONCANONICAL = b'\xa2\x1a\x00\x00\x03\xe8\x63ext\x01\x27'

# canonical encoding of the same header map, for comparison
PHDR_CANONICAL = cbor2.dumps({1: -8, 1000: 'ext'}, canonical=True)

# minimal protected bucket: {1: -8} (alg = EdDSA)
PHDR_EDDSA = b'\xa1\x01\x27'

EMPTY_UHDR = b'\xa0'


@pytest.fixture(scope='module')
def ed25519_key():
    return OKPKey.generate_key(crv='ED25519', optional_params={'ALG': 'EdDSA'})


def sign_message(phdr_raw: bytes, payload: bytes, key, uhdr_raw: bytes = EMPTY_UHDR,
                 tagged: bool = True, external_aad: bytes = b'', detached: bool = False) -> bytes:
    """Sign over the exact protected-bucket bytes and assemble the message manually."""
    msg = Sign1Message(phdr_encoded=phdr_raw,
                       payload=None if detached else payload,
                       external_aad=external_aad)
    msg.key = key
    sig = msg.compute_signature(detached_payload=payload) if detached else msg.compute_signature()
    payload_item = b'\xf6' if detached else bstr(payload)
    return sign1_bytes(phdr_raw, uhdr_raw, payload_item, bstr(sig), tagged)


def unsigned_message(phdr_raw: bytes, uhdr_raw: bytes = EMPTY_UHDR,
                     payload_item: bytes = b'\x40', sig_item: bytes = b'\x40',
                     tagged: bool = True) -> bytes:
    """Assemble a message with a dummy (invalid) signature, for decode-only tests."""
    return sign1_bytes(phdr_raw, uhdr_raw, payload_item, sig_item, tagged)


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------

def test_strict_noncanonical_protected_bytes_signed_and_preserved(ed25519_key):
    assert PHDR_NONCANONICAL != PHDR_CANONICAL  # key order and integer width differ

    encoded = sign_message(PHDR_NONCANONICAL, b'hello world', ed25519_key)
    assert bstr(PHDR_NONCANONICAL) in encoded

    msg = Sign1Message.decode_strict(encoded)
    msg.key = ed25519_key

    assert msg.verify_signature()
    # the received bytes are kept verbatim, never re-encoded
    assert msg.phdr_encoded == PHDR_NONCANONICAL
    # unknown, non-critical extension header is preserved
    assert msg.phdr[1000] == 'ext'
    assert msg.get_attr(headers.Algorithm).fullname == 'EDDSA'


def test_strict_original_bytes_are_what_get_verified(ed25519_key):
    # sign over the non-canonical protected bytes
    msg = Sign1Message(phdr_encoded=PHDR_NONCANONICAL, payload=b'hello world')
    msg.key = ed25519_key
    sig = msg.compute_signature()

    # same signature, but the protected bucket is re-encoded canonically
    # (keys reordered, integer shortened): verification must now fail
    tampered = sign1_bytes(PHDR_CANONICAL, EMPTY_UHDR, bstr(b'hello world'), bstr(sig))
    msg = Sign1Message.decode_strict(tampered)
    msg.key = ed25519_key
    assert not msg.verify_signature()


def test_strict_untagged_accepted(ed25519_key):
    encoded = sign_message(PHDR_EDDSA, b'hello world', ed25519_key, tagged=False)
    msg = Sign1Message.decode_strict(encoded)
    msg.key = ed25519_key
    assert msg.verify_signature()


def test_strict_empty_payload(ed25519_key):
    encoded = sign_message(PHDR_EDDSA, b'', ed25519_key)
    msg = Sign1Message.decode_strict(encoded)
    msg.key = ed25519_key
    assert msg.payload == b''
    assert msg.verify_signature()


def test_strict_detached_payload(ed25519_key):
    payload = b'detached content'
    encoded = sign_message(PHDR_EDDSA, payload, ed25519_key, detached=True)

    msg = Sign1Message.decode_strict(encoded)
    msg.key = ed25519_key
    assert msg.payload is None
    assert msg.verify_signature(detached_payload=payload)

    with pytest.raises(CoseException, match="Missing payload"):
        msg.verify_signature()


def test_strict_external_aad(ed25519_key):
    aad = b'extra authenticated data'
    encoded = sign_message(PHDR_EDDSA, b'hello world', ed25519_key, external_aad=aad)

    msg = Sign1Message.decode_strict(encoded)
    msg.key = ed25519_key
    msg.external_aad = aad
    assert msg.verify_signature()

    msg.external_aad = b'wrong aad'
    assert not msg.verify_signature()


def test_strict_unknown_noncritical_extension_in_unprotected(ed25519_key):
    # unprotected bucket: {1000: "ext", 4: h'01'} (unknown extension + kid)
    uhdr_raw = b'\xa2\x19\x03\xe8\x63ext\x04\x41\x01'
    encoded = sign_message(PHDR_EDDSA, b'hello world', ed25519_key, uhdr_raw=uhdr_raw)

    msg = Sign1Message.decode_strict(encoded)
    msg.key = ed25519_key
    assert msg.verify_signature()
    assert msg.uhdr[1000] == 'ext'
    assert msg.get_attr(headers.KID) == b'\x01'


def test_strict_critical_extension_understood(ed25519_key):
    # protected: {1: -8, 2: [-65537], -65537: h'78'}
    phdr_raw = (b'\xa3\x01\x27\x02\x81\x3a\x00\x01\x00\x00'
                b'\x3a\x00\x01\x00\x00\x41\x78')
    encoded = sign_message(phdr_raw, b'hello world', ed25519_key)

    msg = Sign1Message.decode_strict(encoded, understood_crit=[-65537])
    msg.key = ed25519_key
    assert msg.verify_signature()
    assert msg.phdr[-65537] == b'\x78'


# ---------------------------------------------------------------------------
# structural rejection
# ---------------------------------------------------------------------------

def test_strict_rejects_trailing_data(ed25519_key):
    encoded = sign_message(PHDR_EDDSA, b'hello world', ed25519_key)
    with pytest.raises(CoseMalformedMessage, match="Trailing data"):
        Sign1Message.decode_strict(encoded + b'\x00')


def test_strict_rejects_wrong_item_count():
    for array_header in (b'\x83', b'\x85'):  # 3 and 5 items
        encoded = (b'\xd2' + array_header + bstr(PHDR_EDDSA) + EMPTY_UHDR + b'\x40' + b'\x40')
        with pytest.raises(CoseMalformedMessage, match="exactly 4 items"):
            Sign1Message.decode_strict(encoded)


def test_strict_rejects_wrong_tag():
    encoded = b'\xd3' + b'\x84' + bstr(PHDR_EDDSA) + EMPTY_UHDR + b'\x40' + b'\x40'  # tag 19
    with pytest.raises(CoseMalformedMessage, match="tag 18"):
        Sign1Message.decode_strict(encoded)


def test_strict_rejects_wrong_types():
    # protected bucket as a bare map instead of a bstr
    with pytest.raises(CoseMalformedMessage, match="byte string"):
        Sign1Message.decode_strict(b'\xd2\x84' + PHDR_EDDSA + EMPTY_UHDR + b'\x40' + b'\x40')

    # unprotected bucket as a bstr instead of a map
    with pytest.raises(CoseMalformedMessage, match="map"):
        Sign1Message.decode_strict(b'\xd2\x84' + bstr(PHDR_EDDSA) + b'\x40' + b'\x40' + b'\x40')

    # payload as an integer
    with pytest.raises(CoseMalformedMessage, match="[Pp]ayload"):
        Sign1Message.decode_strict(b'\xd2\x84' + bstr(PHDR_EDDSA) + EMPTY_UHDR + b'\x01' + b'\x40')

    # signature as an integer
    with pytest.raises(CoseMalformedMessage, match="[Ss]ignature"):
        Sign1Message.decode_strict(b'\xd2\x84' + bstr(PHDR_EDDSA) + EMPTY_UHDR + b'\x40' + b'\x01')

    # top-level item is not an array
    with pytest.raises(CoseMalformedMessage, match="array"):
        Sign1Message.decode_strict(b'\xd2\xa0')


def test_strict_rejects_non_bytes_input():
    with pytest.raises(TypeError):
        Sign1Message.decode_strict("not bytes")


# ---------------------------------------------------------------------------
# duplicate labels (hand-crafted maps, never encoded through a Python dict)
# ---------------------------------------------------------------------------

def test_strict_rejects_duplicate_label_in_protected():
    # protected: {1: -8, 1: -8}
    phdr_raw = b'\xa2\x01\x27\x01\x27'
    with pytest.raises(CoseMalformedMessage, match="[Dd]uplicate.*protected"):
        Sign1Message.decode_strict(unsigned_message(phdr_raw))


def test_strict_rejects_duplicate_label_by_value_not_by_encoding():
    # protected: {1: -8, 1: -8} where the second key 1 is encoded non-shortest as 0x18 0x01
    phdr_raw = b'\xa2\x01\x27\x18\x01\x27'
    with pytest.raises(CoseMalformedMessage, match="[Dd]uplicate.*protected"):
        Sign1Message.decode_strict(unsigned_message(phdr_raw))


def test_strict_rejects_duplicate_label_in_unprotected():
    # unprotected: {4: h'01', 4: h'02'}
    uhdr_raw = b'\xa2\x04\x41\x01\x04\x41\x02'
    with pytest.raises(CoseMalformedMessage, match="[Dd]uplicate.*unprotected"):
        Sign1Message.decode_strict(unsigned_message(PHDR_EDDSA, uhdr_raw))


def test_strict_rejects_label_in_both_buckets():
    # alg (label 1) in protected and in unprotected
    uhdr_raw = b'\xa1\x01\x27'
    with pytest.raises(CoseMalformedMessage, match="both"):
        Sign1Message.decode_strict(unsigned_message(PHDR_EDDSA, uhdr_raw))


def test_strict_rejects_trailing_data_inside_protected():
    # protected bstr content: a valid map followed by an extra item
    phdr_raw = b'\xa1\x01\x27\x00'
    with pytest.raises(CoseMalformedMessage, match="[Tt]railing data inside the protected"):
        Sign1Message.decode_strict(unsigned_message(phdr_raw))


# ---------------------------------------------------------------------------
# algorithm / critical header rules
# ---------------------------------------------------------------------------

def test_strict_rejects_missing_algorithm():
    # protected: {4: h'01'} (kid only, no alg)
    with pytest.raises(CoseMalformedMessage, match="Algorithm"):
        Sign1Message.decode_strict(unsigned_message(b'\xa1\x04\x41\x01'))

    # empty protected bucket
    with pytest.raises(CoseMalformedMessage, match="Algorithm"):
        Sign1Message.decode_strict(unsigned_message(b''))

    # alg only in unprotected
    with pytest.raises(CoseMalformedMessage, match="Algorithm"):
        Sign1Message.decode_strict(unsigned_message(b'', b'\xa1\x01\x27'))


def test_strict_rejects_unknown_critical_label():
    # protected: {1: -8, 2: [-65537], -65537: h'78'}
    phdr_raw = (b'\xa3\x01\x27\x02\x81\x3a\x00\x01\x00\x00'
                b'\x3a\x00\x01\x00\x00\x41\x78')
    with pytest.raises(CoseException, match="not understood"):
        Sign1Message.decode_strict(unsigned_message(phdr_raw))


def test_strict_rejects_critical_in_unprotected():
    uhdr_raw = b'\xa1\x02\x81\x01'  # {2: [1]}
    with pytest.raises(CoseMalformedMessage, match="Critical"):
        Sign1Message.decode_strict(unsigned_message(PHDR_EDDSA, uhdr_raw))


def test_strict_rejects_critical_label_not_present():
    # protected: {1: -8, 2: [4]} -- label 4 listed critical but absent
    phdr_raw = b'\xa2\x01\x27\x02\x81\x04'
    with pytest.raises(CoseMalformedMessage, match="not present"):
        Sign1Message.decode_strict(unsigned_message(phdr_raw), understood_crit=[4])


def test_strict_rejects_duplicate_labels_in_critical():
    # protected: {1: -8, 2: [-65537, -65537], -65537: h'78'}
    phdr_raw = (b'\xa3\x01\x27\x02\x82\x3a\x00\x01\x00\x00\x3a\x00\x01\x00\x00'
                b'\x3a\x00\x01\x00\x00\x41\x78')
    with pytest.raises(CoseMalformedMessage, match="[Dd]uplicate.*Critical"):
        Sign1Message.decode_strict(unsigned_message(phdr_raw), understood_crit=[-65537])


def test_strict_rejects_malformed_critical_value():
    # protected: {1: -8, 2: -65537} -- critical value is not an array
    phdr_raw = b'\xa2\x01\x27\x02\x3a\x00\x01\x00\x00'
    with pytest.raises(CoseMalformedMessage, match="CRITICAL"):
        Sign1Message.decode_strict(unsigned_message(phdr_raw), understood_crit=[-65537])


# ---------------------------------------------------------------------------
# the lenient decoder keeps its compatible behavior
# ---------------------------------------------------------------------------

def test_lenient_decode_still_accepts_duplicate_labels():
    # protected: {1: -8, 1: -8} -- the regular decode path silently collapses the map
    phdr_raw = b'\xa2\x01\x27\x01\x27'
    msg = Sign1Message.decode(unsigned_message(phdr_raw, sig_item=bstr(b'\x00' * 64)))
    assert isinstance(msg, Sign1Message)
    assert msg.get_attr(headers.Algorithm).fullname == 'EDDSA'
