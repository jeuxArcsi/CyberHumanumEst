import cryptos
import numpy as np

# Generate a random private key
valid_private_key = False
while not valid_private_key:
    # The base key was found by a single call to cryptos.random_key()
    # Its presence will ensure the generated address is not in the list of
    # know weak addresses (i.e. the addresses whose private keys are in [0: 2**32-1]).
    # The base key must be disclosed to the challenge participants for them to find the
    # key.
    base_key = '8a650c74f99596370fb8b7ac90875130996b432adf80e341dff13a7ec1fe0e34'
    decoded_base_key = cryptos.decode_privkey(base_key, 'hex')
    shitty_random_number = np.random.randint(2**16-1, dtype=np.uint16)
    decoded_private_key = decoded_base_key + shitty_random_number
    private_key = cryptos.encode_privkey(decoded_private_key, 'hex')
    valid_private_key = 0 < decoded_private_key < cryptos.N

print("Private Key (hex) is: ", private_key)
print("Private Key (decimal) is: ", decoded_private_key)

# Convert private key to WIF format
wif_encoded_private_key = cryptos.encode_privkey(decoded_private_key, 'wif')
print("Private Key (WIF) is: ", wif_encoded_private_key)

# Add suffix "01" to indicate a compressed private key
compressed_private_key = private_key + '01'
print("Private Key Compressed (hex) is: ", compressed_private_key)

# Generate a WIF format from the compressed private key (WIF-compressed)
wif_compressed_private_key = cryptos.encode_privkey(
    cryptos.decode_privkey(compressed_private_key, 'hex'), 'wif_compressed')
print("Private Key (WIF-Compressed) is: ", wif_compressed_private_key)

# Multiply the EC generator point G with the private key to get a public key point
public_key = cryptos.fast_multiply(cryptos.G, decoded_private_key)
print("Public Key (x,y) coordinates is:", public_key)

# Encode as hex, prefix 04
hex_encoded_public_key = cryptos.encode_pubkey(public_key, 'hex')
print("Public Key (hex) is:", hex_encoded_public_key)

# Compress public key, adjust prefix depending on whether y is even or odd
(public_key_x, public_key_y) = public_key
compressed_prefix = '02' if (public_key_y % 2) == 0 else '03'
hex_compressed_public_key = compressed_prefix + (cryptos.encode(public_key_x, 16).zfill(64))
print("Compressed Public Key (hex) is:", hex_compressed_public_key)

# Generate bitcoin address from public key
print("Bitcoin Address (b58check) is:", cryptos.pubkey_to_address(public_key))

# Generate compressed bitcoin address from compressed public key
print("Compressed Bitcoin Address (b58check) is:",
      cryptos.pubkey_to_address(hex_compressed_public_key))
