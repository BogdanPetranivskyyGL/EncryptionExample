# EncryptionExample

Hybrid encryption of a file for several servers, with BouncyCastle on .NET Framework 4.8.

- Every server has its own RSA-2048 key pair; the client knows all public keys.
- `Client.Save` generates a random AES-256 key and a 12-byte IV and encrypts the file with AES-GCM. It encrypts
  the AES key (RSA-OAEP-SHA256) with every server's public key and stores each result in the `KeyTable` next to
  the SHA-256 hash of that public key. It adds the current user (`Client.GetEmail`) to the permissions and signs
  them.
- `Client.Open` sends only `KeyTable` and `Permissions` to a server's key endpoint (`Server.GetKey`). The server
  finds its row by its own `PubKeyHash` and unwraps the AES key. It checks the permissions signature, then the
  access level and the signed-in user, and only then returns the key. The client decrypts the content itself.

```json
{
  "Version": 1,
  "Algorithm": "AES-256-GCM",
  "KeyWrap": "RSA-OAEP-SHA256",
  "KeyTable": [
    { "PubKeyHash": "<base64 SHA-256 of the public key>", "Key": "<base64 RSA-encrypted AES key>" }
  ],
  "Permissions": {
    "Data": { "Revision": 1, "AccessType": "SpecificUsers", "Users": [ "USER@EXAMPLE.COM" ] },
    "Sig": "<base64 HMAC-SHA256>"
  },
  "IV": "<base64, 12 bytes>",
  "EncryptedData": "<base64 ciphertext + 16-byte tag>"
}
```

Differences from the current format:

- The IV is not RSA-encrypted per server. It is not a secret, so one plain IV for the file is enough.
- AES-GCM instead of a mode without authentication: a modified file fails to decrypt instead of producing
  garbage.
- `Version`, `Algorithm` and `KeyWrap` make it possible to change algorithms later and still read old files.
  They are also authenticated together with the content.
- `PubKeyHash` is fixed as SHA-256 of the DER SubjectPublicKeyInfo (the body of a `PUBLIC KEY` PEM).

## Permissions

- `AccessType`: `All` (anyone, also anonymous), `Authorized` (any signed-in user), `SpecificUsers` (only `Users`).
- `Users` are trimmed, upper-invariant, de-duplicated and sorted.
- `Sig` is HMAC-SHA256 with a key derived by HKDF-SHA256 from the file's AES key (no salt, info
  `EncryptionExample/permissions/hmac-sha256/v1`). A signature does not fit another file.
- The HMAC covers a fixed text layout (`permissions-v1\n{Revision}\n{AccessType}\n{user}\n...`), not the JSON, so
  re-serializing does not break it.
- The signing key comes from the file key, and the client receives that key on open. So any user allowed to open
  the file can also re-sign changed permissions. If only servers may change permissions, the signing key has to
  come from a secret the servers hold.

## Run

```
EncryptionExample demo
```

Generates three servers in memory, saves a sample section, prints the file and the key request, then opens it
as different users through different servers. It also shows that an unknown server, forged permissions and a
tampered file are refused.

With files:

```
EncryptionExample keygen server-a
EncryptionExample keygen server-b
EncryptionExample encrypt section.xml section.enc.json specific:alice@example.com
EncryptionExample decrypt section.enc.json server-b section.out.xml alice@example.com
```

Keys go to `keys\` in the current directory. `encrypt` uses every `keys\*.public.pem`. Its access argument is
`all`, `authorized` or `specific[:<email>,...]` (the default is `specific`, only the saving user). The last
argument of `decrypt` is the user signed in to the server; omit it for an anonymous request.
