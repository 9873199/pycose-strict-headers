import json,cbor2
from pycose.messages import Sign1Message
from test_cose_contract import make
examples=[('missing numeric critical label',b'\xa3\x01\x27\x02\x81\x04\x63KID\x41k'),('text critical label not declared understood',b'\xa3\x01\x27\x02\x81\x63KID\x63KID\x41k')]
for label,protected in examples:
    wire,key=make(protected)
    try:
        msg=Sign1Message.decode_strict(wire,understood_crit={4})
    except Exception as error:
        observation={'case':label,'strict_decode':'REJECTED','error':str(error)}
    else:
        msg.key=key
        observation={'case':label,'received_header_repr':repr(cbor2.loads(protected)),'caller_understands':[4],'strict_decode':'ACCEPTED','signature_valid':msg.verify_signature(),'original_protected_bytes_preserved':msg.phdr_encoded==protected}
    print(json.dumps(observation,ensure_ascii=False))
