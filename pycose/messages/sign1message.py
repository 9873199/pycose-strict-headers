import io
from typing import Any, Iterable, List, Optional, Tuple, Union, TYPE_CHECKING

import cbor2

from pycose import utils
from pycose.headers import CoseHeaderAttribute, Algorithm, Critical, crit_is_array
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.signcommon import SignCommon
from pycose.exceptions import CoseException, CoseMalformedMessage

if TYPE_CHECKING:
    from pycose.keys.ec2 import EC2
    from pycose.keys.okp import OKP
    from pycose.keys.rsa import RSA

CBOR = bytes


class _StrictCborReader:
    """
    Minimal CBOR reader used by the strict decoder.

    Unlike ``cbor2.loads`` it does not collapse CBOR maps into Python dicts
    (so duplicate map keys stay visible) and it tracks how many input bytes
    were consumed (so trailing data can be rejected).
    """

    def __init__(self, data: bytes):
        self._fp = io.BytesIO(data)
        self._decoder = cbor2.CBORDecoder(self._fp)
        self._len = len(data)

    def _read_exact(self, n: int) -> bytes:
        chunk = self._fp.read(n)
        if len(chunk) != n:
            raise CoseMalformedMessage("Truncated CBOR data")
        return chunk

    def read_header(self) -> Tuple[int, Optional[int]]:
        """ Reads a CBOR item header, returns (major type, argument); an argument of None means indefinite length. """
        initial = self._read_exact(1)[0]
        major, info = initial >> 5, initial & 0x1F
        if info < 24:
            arg = info
        elif info == 24:
            arg = int.from_bytes(self._read_exact(1), 'big')
        elif info == 25:
            arg = int.from_bytes(self._read_exact(2), 'big')
        elif info == 26:
            arg = int.from_bytes(self._read_exact(4), 'big')
        elif info == 27:
            arg = int.from_bytes(self._read_exact(8), 'big')
        elif info == 31:
            arg = None
        else:
            raise CoseMalformedMessage("Reserved CBOR additional information")

        if arg is None and major not in (2, 3, 4, 5):
            raise CoseMalformedMessage("Indefinite length not allowed for this CBOR major type")

        return major, arg

    def read_item(self) -> Any:
        try:
            return self._decoder.decode()
        except Exception as err:
            raise CoseMalformedMessage(f"Invalid CBOR item: {err}") from err

    def at_break(self) -> bool:
        pos = self._fp.tell()
        marker = self._fp.read(1)
        self._fp.seek(pos)
        return marker == b'\xff'

    def read_break(self) -> None:
        if self._read_exact(1) != b'\xff':
            raise CoseMalformedMessage("Expected CBOR break code")

    def exhausted(self) -> bool:
        return self._fp.tell() == self._len


def _read_map_pairs(reader: _StrictCborReader) -> List[Tuple[Any, Any]]:
    """ Reads a CBOR map as a list of (key, value) pairs, preserving duplicates. """
    major, arg = reader.read_header()
    if major != 5:
        raise CoseMalformedMessage("Expected a CBOR map for the header bucket")

    pairs = []
    if arg is None:
        while not reader.at_break():
            pairs.append((reader.read_item(), reader.read_item()))
        reader.read_break()
    else:
        for _ in range(arg):
            pairs.append((reader.read_item(), reader.read_item()))

    return pairs


def _canonical_label_encoding(label: Any) -> bytes:
    """ Canonical re-encoding of a decoded CBOR value, used to compare labels by value and not by encoding. """
    try:
        return cbor2.dumps(label, canonical=True)
    except Exception:
        return repr(label).encode('utf-8')


def _label_identity(label: Any) -> Tuple[str, Any]:
    """
    Identity of a header label: registered COSE header attributes are compared by their identifier
    (so e.g. 1 and "ALG" denote the same label), unknown labels are compared by CBOR value.
    """
    attr = CoseHeaderAttribute.from_id(label, allow_unknown_attributes=True)
    if isinstance(attr, type) and issubclass(attr, CoseHeaderAttribute):
        return 'registered', attr.identifier
    return 'raw', _canonical_label_encoding(label)


def _find_duplicate_labels(labels: Iterable[Any]) -> List[Any]:
    seen = set()
    duplicates = []
    for label in labels:
        identity = _label_identity(label)
        if identity in seen:
            duplicates.append(label)
        else:
            seen.add(identity)
    return duplicates


@CoseMessage.record_cbor_tag(18)
class Sign1Message(SignCommon):
    context = "Signature1"
    cbor_tag = 18

    @classmethod
    def decode_strict(cls, received: bytes, understood_crit: Optional[Iterable] = None,
                      allow_unknown_attributes: bool = True) -> 'Sign1Message':
        """
        Strictly decode a COSE_Sign1 message.

        In contrast to :func:`CoseMessage.decode`, this entry point rejects ambiguous or
        contract-violating encodings instead of silently repairing them:

        - the message must be a single CBOR item: either CBOR tag 18 wrapping a 4-element
          array, or a bare 4-element array; trailing data, wrong item counts and wrong
          item types are rejected;
        - the protected and unprotected header buckets must not contain duplicate labels
          (compared by CBOR value, not by encoding, so e.g. a label encoded in a
          non-shortest form still collides with its shortest form), and no label may
          appear in both buckets;
        - the Algorithm header parameter must be present in the protected bucket;
        - the Critical header parameter is only allowed in the protected bucket, must not
          list the same label twice, may only list labels that are actually present in the
          protected bucket, and every listed label must be part of ``understood_crit``;
        - the original bytes of the protected header bucket are preserved and used for
          signature verification; they are never re-encoded, reordered or canonicalized.

        Unknown, non-critical extension header parameters are kept. A failed decode raises
        an exception and never returns a partially initialized message.

        :param received: COSE_Sign1 message encoded as bytes
        :param understood_crit: iterable of header labels (int, str or CoseHeaderAttribute)
            the caller understands; required when the message carries a Critical parameter
        :param allow_unknown_attributes: allow unknown header attributes in the buckets

        :raises TypeError: when ``received`` is not bytes
        :raises CoseMalformedMessage: when the message violates the structural rules above
        :raises CoseException: when a critical header label is not understood
        :returns: An initialized Sign1Message
        """

        if not isinstance(received, (bytes, bytearray)):
            raise TypeError("Strict decode accepts only bytes as input.")

        reader = _StrictCborReader(bytes(received))

        major, arg = reader.read_header()
        if major == 6:
            if arg != cls.cbor_tag:
                raise CoseMalformedMessage(f"Expected CBOR tag {cls.cbor_tag} (COSE_Sign1), got tag {arg}")
            major, arg = reader.read_header()

        if major != 4:
            raise CoseMalformedMessage("COSE_Sign1 must be a CBOR array of 4 items")
        if arg is not None and arg != 4:
            raise CoseMalformedMessage(f"COSE_Sign1 must contain exactly 4 items, found {arg}")

        # item 1: protected header bucket, a bstr wrapping the serialized header map
        phdr_encoded = reader.read_item()
        if type(phdr_encoded) is not bytes:
            raise CoseMalformedMessage("The protected header bucket must be a byte string")

        # item 2: unprotected header bucket, read as pairs so duplicate labels stay visible
        uhdr_pairs = _read_map_pairs(reader)

        # item 3: payload (bstr, or null for a detached payload)
        payload = reader.read_item()
        if payload is not None and type(payload) is not bytes:
            raise CoseMalformedMessage("The payload must be a byte string or null (detached payload)")

        # item 4: signature
        signature = reader.read_item()
        if type(signature) is not bytes:
            raise CoseMalformedMessage("The signature must be a byte string")

        if arg is None:  # indefinite-length array
            if not reader.at_break():
                raise CoseMalformedMessage("COSE_Sign1 must contain exactly 4 items")
            reader.read_break()

        if not reader.exhausted():
            raise CoseMalformedMessage("Trailing data after the COSE_Sign1 message")

        # parse the protected bucket from its original bytes, again as pairs
        if phdr_encoded == b'':
            phdr_pairs = []
        else:
            phdr_reader = _StrictCborReader(phdr_encoded)
            phdr_pairs = _read_map_pairs(phdr_reader)
            if not phdr_reader.exhausted():
                raise CoseMalformedMessage("Trailing data inside the protected header bucket")

        for bucket, pairs in (("protected", phdr_pairs), ("unprotected", uhdr_pairs)):
            duplicates = _find_duplicate_labels(k for k, _ in pairs)
            if duplicates:
                raise CoseMalformedMessage(f"Duplicate header label(s) {duplicates} in the {bucket} bucket")

        phdr_identities = {_label_identity(k) for k, _ in phdr_pairs}
        uhdr_identities = {_label_identity(k) for k, _ in uhdr_pairs}

        if phdr_identities & uhdr_identities:
            raise CoseMalformedMessage("Header label(s) present in both the protected and the unprotected bucket")

        if _label_identity(Algorithm) not in phdr_identities:
            raise CoseMalformedMessage("The Algorithm header parameter must be present in the protected bucket")

        crit_identity = _label_identity(Critical)
        if crit_identity in uhdr_identities:
            raise CoseMalformedMessage("The Critical header parameter is only allowed in the protected bucket")

        if crit_identity in phdr_identities:
            crit_value = next(v for k, v in phdr_pairs if _label_identity(k) == crit_identity)
            try:
                crit_is_array(crit_value)
            except ValueError as err:
                raise CoseMalformedMessage(str(err)) from err

            if _find_duplicate_labels(crit_value):
                raise CoseMalformedMessage("Duplicate label(s) in the Critical header parameter")

            understood = {_label_identity(label) for label in (understood_crit or [])}
            for label in crit_value:
                identity = _label_identity(label)
                if identity not in phdr_identities:
                    raise CoseMalformedMessage(
                        f"Critical label {label!r} is not present in the protected bucket")
                if identity not in understood:
                    raise CoseException(f"Critical header label {label!r} is not understood by the caller")

        try:
            uhdr = dict(uhdr_pairs)
        except TypeError as err:
            raise CoseMalformedMessage(f"Unhashable header label in the unprotected bucket: {err}") from err

        msg = cls(phdr_encoded=phdr_encoded, uhdr=uhdr, payload=payload,
                  allow_unknown_attributes=allow_unknown_attributes)
        msg.signature = signature
        return msg

    @classmethod
    def from_cose_obj(cls, cose_obj, allow_unknown_attributes: bool) -> 'Sign1Message':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg._signature = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: Optional[bytes] = None,
                 external_aad: bytes = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

        self._signature = b''

    @property
    def signature(self):
        return self._signature
    
    @signature.setter
    def signature(self, value):
        if not isinstance(value, bytes):
            raise TypeError("Signature must be of type 'bytes'")

        self._signature = value

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None):
        """
        Create the sig_structure that needs to be signed

        :return: to_be_signed
        """
        sig_structure = [self.context]
        sig_structure = self._base_structure(sig_structure)

        if detached_payload is None:
            if self.payload is None:
                raise CoseException("Missing payload and no detached payload provided")
            sig_structure.append(self.payload)
        else:
            if self.payload is not None:
                raise CoseException("Detached payload must be None when payload is set")
            sig_structure.append(detached_payload)

        return cbor2.dumps(sig_structure)

    def encode(self, tag: bool = True, sign: bool = True, detached_payload: Optional[bytes] = None, *args, **kwargs) -> CBOR:
        """ Encodes the message into a CBOR array with or without a CBOR tag. """

        if sign:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload, self.compute_signature(detached_payload)]
        elif self.signature:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload, self.signature]
        else:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        if tag:
            res = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._custom_cbor_encoder)
        else:
            res = cbor2.dumps(message, default=self._custom_cbor_encoder)

        return res

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Sign1: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, ' \
               f'{utils.truncate(self._signature)}]>'
