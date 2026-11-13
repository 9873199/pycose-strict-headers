"""Raw CBOR ambiguity tests and genuine signatures over unmodified protected bytes."""
import cbor2,pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pycose.keys import OKPKey
from pycose.keys.curves import Ed25519
from pycose.messages import Sign1Message

def make(protected=b'\xa1\x01\x27',unprotected=b'\xa0',payload=b'content',*,aad=b'',detached=False,tagged=True):
 private=Ed25519PrivateKey.generate();public=private.public_key()
 key=OKPKey(crv=Ed25519,x=public.public_bytes_raw(),d=private.private_bytes_raw())
 signature=private.sign(cbor2.dumps(['Signature1',protected,aad,payload]))
 wire=(b'\xd2' if tagged else b'')+b'\x84'+cbor2.dumps(protected)+unprotected+cbor2.dumps(None if detached else payload)+cbor2.dumps(signature)
 return wire,key

@pytest.fixture
def strict():
 # This adapter is written only after reviewing the actual published entrypoint.
 # Its naming is deliberately independent of the task's implementation choices.
 from acceptance_adapter import strict_decode_sign1
 return strict_decode_sign1

@pytest.mark.parametrize('tagged',[True,False])
@pytest.mark.parametrize('payload',[b'content',b''])
def test_legal_signatures(strict,tagged,payload):
 wire,key=make(payload=payload,tagged=tagged);message=strict(wire)
 message.key=key;assert message.payload==payload and message.verify_signature()

def test_noncanonical_protected_original_bytes_are_signed(strict):
 # Map order is KID then Algorithm; both Algorithm's key and value are non-shortest.
 protected=b'\xa2\x04\x41k\x18\x01\x38\x07'
 wire,key=make(protected);message=strict(wire);message.key=key
 assert message.phdr_encoded==protected and message.verify_signature()

def test_detached_payload_and_external_aad(strict):
 wire,key=make(payload=b'detached content',aad=b'business context',detached=True)
 message=strict(wire);message.key=key;message.external_aad=b'business context'
 assert message.payload is None and message.verify_signature(detached_payload=b'detached content')
 message.external_aad=b'changed context'
 assert not message.verify_signature(detached_payload=b'detached content')

@pytest.mark.parametrize('protected',[
 b'\xa2\x01\x27\x01\x27',
 b'\xa2\x01\x27\x18\x01\x27',
 b'\xa3\x01\x27\x61x\x01\x7f\x61x\xff\x02',
 b'\xa1\x01\x27\x00'])
def test_protected_duplicates_or_trailing_objects_rejected(strict,protected):
 wire,_=make(protected)
 with pytest.raises(Exception):strict(wire)

@pytest.mark.parametrize('unprotected',[
 b'\xa2\x04\x41a\x04\x41b',
 b'\xa2\x04\x41a\x18\x04\x41b',
 b'\xa1\x01\x27',
 b'\xa1\x02\x81\x04'])
def test_unprotected_duplicates_conflicts_and_critical_rejected(strict,unprotected):
 wire,_=make(unprotected=unprotected)
 with pytest.raises(Exception):strict(wire)

@pytest.mark.parametrize('critical',[[4,4],[999]])
def test_invalid_critical_list_rejected(strict,critical):
 # Only the task's explicit duplicate/missing-label rules are asserted here.
 protected=cbor2.dumps({1:-8,2:critical,4:b'kid'})
 wire,_=make(protected)
 with pytest.raises(Exception):strict(wire,understood={4})

def test_understood_critical_extension(strict):
 protected=cbor2.dumps({1:-8,2:[999],999:b'extension'})
 wire,key=make(protected)
 with pytest.raises(Exception):strict(wire,understood=set())
 message=strict(wire,understood={999});message.key=key;assert message.verify_signature()

def test_unknown_noncritical_extension_is_preserved(strict):
 wire,key=make(cbor2.dumps({1:-8,999:b'extension'}));message=strict(wire);message.key=key
 assert message.verify_signature() and message.phdr_encoded==cbor2.dumps({1:-8,999:b'extension'})

def test_missing_protected_algorithm_rejected(strict):
 wire,_=make(b'\xa0',unprotected=cbor2.dumps({1:-8}))
 with pytest.raises(Exception):strict(wire)

def test_outer_trailing_object_rejected(strict):
 wire,_=make()
 with pytest.raises(Exception):strict(wire+b'\x00')

@pytest.mark.parametrize('shape',[
 [b'\xa1\x01\x27',{},b'content'],
 [b'\xa1\x01\x27',{},b'content',b'signature',0],
 [{1:-8},{},b'content',b'signature'],
 [b'\xa1\x01\x27',[],b'content',b'signature'],
 [b'\xa1\x01\x27',{},42,b'signature'],
 [b'\xa1\x01\x27',{},b'content',42]])
def test_outer_contract_types(strict,shape):
 with pytest.raises(Exception):strict(cbor2.dumps(cbor2.CBORTag(18,shape)))

if __name__=='__main__':
 for protected,payload,detached,aad in [(b'\xa1\x01\x27',b'content',False,b''),(b'\xa2\x04\x41k\x18\x01\x38\x07',b'',False,b''),(b'\xa1\x01\x27',b'detached content',True,b'context')]:
  wire,key=make(protected,payload=payload,detached=detached,aad=aad)
  message=Sign1Message.decode(wire);message.key=key;message.external_aad=aad
  assert message.phdr_encoded==protected and message.verify_signature(detached_payload=payload if detached else None)
 print('PASS original Sign1 cryptography validates manually assembled canonical, noncanonical, empty and detached payload cases')
