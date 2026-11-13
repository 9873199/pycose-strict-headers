from pycose.messages import Sign1Message
def strict_decode_sign1(wire,understood=None):
    return Sign1Message.decode_strict(wire,understood_crit=understood)
