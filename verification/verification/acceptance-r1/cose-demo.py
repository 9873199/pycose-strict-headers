from pycose.messages import Sign1Message
from test_cose_contract import make
protected=b'\xa2\x04\x41k\x18\x01\x38\x07'
wire,key=make(protected);msg=Sign1Message.decode_strict(wire);msg.key=key
print('Received protected bytes:',protected.hex())
print('Preserved original bytes:',msg.phdr_encoded==protected)
print('Signature valid:',msg.verify_signature())
wire,key=make(payload=b'detached content',aad=b'business context',detached=True)
msg=Sign1Message.decode_strict(wire);msg.key=key;msg.external_aad=b'business context'
print('Detached payload and external AAD valid:',msg.verify_signature(detached_payload=b'detached content'))
for label,wire in [('Duplicate protected label',make(b'\xa2\x01\x27\x18\x01\x27')[0]),('Trailing CBOR',make()[0]+b'\x00')]:
    try:
        Sign1Message.decode_strict(wire);print(label+': accepted')
    except Exception as error:
        print(label+': '+type(error).__name__+': '+str(error))
