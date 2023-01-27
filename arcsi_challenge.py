import cryptos
import numpy as np

valid_private_key = False
while not valid_private_key:
    base_key = '8a650c74f99596370fb8b7ac90875130996b432adf80e341dff13a7ec1fe0e34'
    decoded_base_key = cryptos.decode_privkey(base_key, 'hex')
    shitty_random_number = np.random.randint(2**16-1, dtype=np.uint16)
    decoded_private_key = decoded_base_key + shitty_random_number
    private_key = cryptos.encode_privkey(decoded_private_key, 'hex')
    valid_private_key = 0 < decoded_private_key < cryptos.N

print("Private Key (hex) is: ", private_key)
print("Private Key (decimal) is: ", decoded_private_key)
wif_encoded_private_key = cryptos.encode_privkey(decoded_private_key, 'wif')
print("Private Key (WIF) is: ", wif_encoded_private_key)
compressed_private_key = private_key + '01'
print("Private Key Compressed (hex) is: ", compressed_private_key)
wif_compressed_private_key = cryptos.encode_privkey(
    cryptos.decode_privkey(compressed_private_key, 'hex'), 'wif_compressed')
print("Private Key (WIF-Compressed) is: ", wif_compressed_private_key)
public_key = cryptos.fast_multiply(cryptos.G, decoded_private_key)
print("Public Key (x,y) coordinates is:", public_key)
hex_encoded_public_key = cryptos.encode_pubkey(public_key, 'hex')
print("Public Key (hex) is:", hex_encoded_public_key)
(public_key_x, public_key_y) = public_key
compressed_prefix = '02' if (public_key_y % 2) == 0 else '03'
hex_compressed_public_key = compressed_prefix + (cryptos.encode(public_key_x, 16).zfill(64))
print("Compressed Public Key (hex) is:", hex_compressed_public_key)
print("Bitcoin Address (b58check) is:", cryptos.pubkey_to_address(public_key))
print("Compressed Bitcoin Address (b58check) is:",
      cryptos.pubkey_to_address(hex_compressed_public_key))
