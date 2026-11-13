import pytest
from pycose.messages import Sign1Message
from test_cose_contract import make

def test_critical_numeric_label_cannot_be_supplied_by_text_alias():
    # {1:-8,2:[4],"KID":h'6b'} has no integer label 4.
    protected=b'\xa3\x01\x27\x02\x81\x04\x63KID\x41k'
    wire,key=make(protected)
    with pytest.raises(Exception):
        Sign1Message.decode_strict(wire,understood_crit={4})

def test_text_critical_label_is_not_understood_by_numeric_alias():
    # Text label "KID" exists but caller explicitly understands only integer 4.
    protected=b'\xa3\x01\x27\x02\x81\x63KID\x63KID\x41k'
    wire,key=make(protected)
    with pytest.raises(Exception):
        Sign1Message.decode_strict(wire,understood_crit={4})

def test_noncritical_text_extension_is_distinct_from_integer_label():
    # Valid distinct CBOR labels: 1, 4 and "KID". This is not a duplicate map.
    protected=b'\xa3\x01\x27\x04\x41a\x63KID\x41b'
    wire,key=make(protected)
    message=Sign1Message.decode_strict(wire);message.key=key
    assert message.phdr_encoded==protected and message.verify_signature()
    assert message.phdr['KID']==b'b'

if __name__=='__main__':
    import cbor2,json
    examples=[('missing numeric critical label',b'\xa3\x01\x27\x02\x81\x04\x63KID\x41k'),('text critical label not declared understood',b'\xa3\x01\x27\x02\x81\x63KID\x63KID\x41k')]
    for label,protected in examples:
        wire,key=make(protected)
        try:
            msg=Sign1Message.decode_strict(wire,understood_crit={4});msg.key=key
            print(json.dumps({'case':label,'received_header':cbor2.loads(protected),'caller_understands':[4],'strict_decode':'ACCEPTED','signature_valid':msg.verify_signature()},ensure_ascii=False))
        except Exception as error:
            print(json.dumps({'case':label,'strict_decode':'REJECTED','error':str(error)},ensure_ascii=False))
