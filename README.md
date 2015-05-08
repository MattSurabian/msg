# MSG

Named after Monosodium Glutamate, the MSG encryption library is written in Go and uses AES256-GCM and NACL to 
facilitate secure data data sharing between multiple parties without need for out of band secret key transmission.

While NaCl is great for securing short messages between two parties, it doesn't support creating a single cipher text for 
multiple recipients. Likewise, AES256-GCM works well for large messages but requires that the secret key or a passphrase 
capable of generating the secret key be communicated out of band.

## Encrypt 
*Signature:* ( **plainText** []byte, **authorizedPubKeys** []*[32]byte, **selfPubKey**, **selfPrivKey** *[32]byte)

*Returns:* []byte

The passed `plainText` is encrypted with AES256-GCM using a randomly generated 32 byte key and a unique salt.
That key is then encrypted with each of the NACL public keys in the `authorizedPubKeys` array.

The returned byte array is assembled like so:

```
gcmNonce(12 bytes) cipherTextLength(10 bytes) cipherText(? bytes) pubKeyOfSecretCreator(32 bytes)
```

The remainder of the blob is made up of repeating 92 byte chunks containing the NaCl encrypted 
AES256-GCM key prefixed with the fingerprint of the public key used for encryption and a unique nonce:

```
usersPubKeyFingerprint(20 bytes) NaClNonce(24 bytes) NaClSecret(48 bytes)
```

## Decrypt
*Signature:* ( **blob** []byte, **selfPubKey**, **selfPrivKey** *[32]byte ) 

*Returns:* []byte, error

The decrypter uses it's knowledge of the encrypted `blob` and breaks it appart into pieces. It loops
through the 92 byte chunks at the end until it finds a key fingerprint that matches the passed in
`selfPubKey`. It then decryptes the NaCl cipher text, and uses that value as the key to decrypt the
large AES256-GCM encrypted cipher text. 

It returns either the plain text in a byte array or a decrytion error.

## Keys
Several helper methods are provided for reading and writing keys for NaCl and AES256-GCM. In order
to use the encryption and decryption functionality you must have a public/private NaCl keypair and 
the public keys of those you wish to encrypt information for.

## Entropy
Helper methods are provided to generate cryptographically secure salts for use with NaCl and AES256-GCM.

## Contributing
If you think this is an interesting idea and want to contribute, please do!