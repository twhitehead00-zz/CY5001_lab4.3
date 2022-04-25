CY5001_lab4.3
=============

 My implementation of the OpenSSL Protect project!


## Build

To build the app make sure *rsa* and *argparse* are installed. These can be easily installed using pip.

```pip install rsa```

```pip install argparse```


I chose to work with the *rsa* package because it is lightweight and easy to use/understand while providing all the desired functionality.


## Usage

The program can perfom five tasks. To run call one of the following


#### Key Generation

```python openssl.py  --keygen True```

* writes keys to current directory


#### Encryption

```python openssl.py  --encrypt True --message (plaintext message)  --key (public key)```

* writes encrypted file to current directory


#### Decryption

```python openssl.py  --decrypt True --message (encrypted message)  --key (private key)```


#### Signing

```python openssl.py  --sign True --message (unsigned message)  --key (private key)```

Signig has an optional parameter ```--hash_function``` which may be specified to use one of the following hash functions:

```'MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'```

The default is ```'SHA-1'``` 

* writes signature block to current directory


#### Verification

```python openssl.py  --verify True --message (signed message) --signature (signature block)  --key (public key)```

 
