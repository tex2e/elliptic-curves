
# Elliptic Curve Diffie Hellman (ecdh)

# RFC 7748
# Elliptic Curves for Security

import binascii
from ec import x25519, x448, encodeUCoordinate

# 6.  Diffie-Hellman

# 6.1.  Curve25519
# Diffie Hellman key exchange over Curve25519
# Test vector:

# Secret key
alice_sec = binascii.unhexlify(
    b'77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
bob_sec = binascii.unhexlify(
    b'5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')

# Create public key
base_point = encodeUCoordinate(9, bits=255)
alice_pub = x25519(alice_sec, base_point)
bob_pub = x25519(bob_sec, base_point)

# Their shared secret
alice_shared_secret = x25519(alice_sec, bob_pub)
bob_shared_secret = x25519(bob_sec, alice_pub)
print(alice_shared_secret)


# Assert public key
expected_alice_pub = binascii.unhexlify(
    b'8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
expected_bob_pub = binascii.unhexlify(
    b'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
assert alice_pub == expected_alice_pub
assert bob_pub == expected_bob_pub

# Assert shared secret
assert alice_shared_secret == bob_shared_secret
expected_shared_secret = binascii.unhexlify(
    b'4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
assert alice_shared_secret == expected_shared_secret



# 6.2.  Curve448
# Diffie Hellman key exchange over Curve448
# Test vector:

# Secret key
alice_sec = binascii.unhexlify(
    b'9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d' +
    b'd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b')
bob_sec = binascii.unhexlify(
    b'1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d' +
    b'6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d')

# Create public key
base_point = encodeUCoordinate(5, bits=448)
alice_pub = x448(alice_sec, base_point)
bob_pub = x448(bob_sec, base_point)

# Their shared secret
alice_shared_secret = x448(alice_sec, bob_pub)
bob_shared_secret = x448(bob_sec, alice_pub)
print(alice_shared_secret)


# Assert public key
expected_alice_pub = binascii.unhexlify(
    b'9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c' +
    b'22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0')
expected_bob_pub = binascii.unhexlify(
    b'3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430' +
    b'27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609')
assert alice_pub == expected_alice_pub
assert bob_pub == expected_bob_pub

# Assert shared secret
assert alice_shared_secret == bob_shared_secret
expected_shared_secret = binascii.unhexlify(
    b'07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b' +
    b'b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d')
assert alice_shared_secret == expected_shared_secret
