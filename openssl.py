import argparse
import rsa


# signs message, writes signature block to current dir
def rsa_sign(message, txt_key, hash_func):
    print('Signing...')
    privkey = rsa.PrivateKey.load_pkcs1(txt_key.encode())
    signature_block = rsa.sign(message, privkey, hash_func)
    print('RSA signed')

    with open('signature_block.txt', 'wb') as o:
        o.write(signature_block)
    exit(0)


# verifies signature
def rsa_verify(message, signature, txt_key):
    print('Verifying...')
    pubkey = rsa.PublicKey.load_pkcs1(txt_key.encode())
    verified_hash_func = rsa.verify(message, signature, pubkey)
    print('Verified')
    print(f'Hash function used: {str(verified_hash_func)}')
    exit(0)


# generates key pairs, writes them to current dir
def keygen():
    pubkey, privkey = rsa.newkeys(1024)
    with open('privkey.pem', 'wt') as o:
        o.write(privkey._save_pkcs1_pem().decode())

    with open('pubkey.pem', 'wt') as o:
        o.write(pubkey._save_pkcs1_pem().decode())

    exit(0)


# encrypts plain text to be signed, writes encrypted file to current dir
def encrypt(plain_text, txt_key):
    pubkey = rsa.PublicKey.load_pkcs1(txt_key.encode())
    crypto = rsa.encrypt(plain_text.encode(), pubkey)
    with open('crypto.sh', 'wb') as o:
        o.write(crypto)
    print('Plain-text file encrypted')
    exit(0)


# decrypts plain text
def decrypt(crypto, txt_key):
    privkey = rsa.PrivateKey.load_pkcs1(txt_key.encode())
    plain_txt = rsa.decrypt(crypto, privkey).decode()
    print('Decrypted message: \n' + str(plain_txt))
    # with open('plain_txt.txt', 'wt') as o:
    #     o.write(plain_txt)
    exit(0)


# sourcery skip: raise-specific-error
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # input params
    parser.add_argument('--key', help='Private or Public Key file', required=False)
    parser.add_argument('--hash_function', help='the hash function to use, default is SHA-1', default='SHA-1')
    parser.add_argument('--signature', help='the file that contains the signature', required=False)
    parser.add_argument('--message', help='the message to sign or that has been signed', required=False)
    # actions
    parser.add_argument('--keygen', help='if True, instructs programme to generate an RSA key pair', default=False, type=bool)
    parser.add_argument('--sign', help='if True, instructs programme to sign', default=False, type=bool)
    parser.add_argument('--verify', help='if True, instructs programme to verify', default=False, type=bool)
    parser.add_argument('--encrypt', help='if True, instructs programme to encrypt', default=False, type=bool)
    parser.add_argument('--decrypt', help='if True, instructs programme to decrypt', default=False, type=bool)

    args = parser.parse_args()
    print(args)

    try:
        if args.keygen:
            keygen()

        # reads in key file
        with open(args.key, 'r') as f:
            key = f.read()

        if args.encrypt:
            with open(args.message, 'r') as f:
                msg = f.read()
            encrypt(msg, key)
        if args.decrypt:
            with open(args.message, 'rb') as f:
                msg = f.read()
            decrypt(msg, key)

        # verify hash function is valid
        hash_func = args.hash_function
        if hash_func not in ['MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512']:
            raise Exception('Invalid hash scheme')
        # reads in message
        with open(args.message, 'rb') as f:
            msg = f.read()

        if args.sign:
            rsa_sign(msg, key, hash_func)
        if args.verify:
            with open(args.signature, 'rb') as f:
                bytes_signature = f.read()
            rsa_verify(msg, bytes_signature, key)

    except Exception:
        print('Invalid input params')
