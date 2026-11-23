# Encrypted API Request Context

## What is implemented

The React/Vite client encrypts the request bodies for:

- `POST /api/v1/auth/login` (email and CAPTCHA fields)
- `POST /api/v1/auth/verify-otp` (email and OTP)

The backend exposes `GET /api/v1/encryption/public-key`. The CAPTCHA endpoint
remains unencrypted. If fetching the key or encrypting a body fails, the client
does not fall back to plaintext. HTTPS is still required; this protocol is an
additional layer, not a replacement for TLS.

## Protocol

- AES-256-GCM encrypts the UTF-8 JSON request body with a fresh 32-byte key and
  12-byte IV for every request.
- RSA-OAEP with SHA-256 wraps the AES key.
- The GCM tag is 16 bytes and is sent separately from the ciphertext.
- Binary values are encoded using standard Base64.
- RSA keys must be at least 2048 bits.

The envelope shape is:

```json
{
  "keyId": "rsa-2026-01",
  "encryptedKey": "<base64 RSA-OAEP-wrapped AES key>",
  "encryptedData": "<base64 AES-GCM ciphertext only>",
  "iv": "<base64 12-byte IV>",
  "authTag": "<base64 16-byte authentication tag>"
}
```

The browser Web Crypto API appends the GCM tag to its encryption result. The
client splits off the final 16 bytes to send `encryptedData` and `authTag`
separately. Never reuse a GCM IV with the same AES key. Do not use AES-ECB or
unauthenticated AES-CBC.

The backend validates the envelope, unwraps the AES key, authenticates and
decrypts the body, parses strict UTF-8 JSON, and replaces `req.body` only after
all checks succeed. The login middleware order is rate limit, decrypt, CAPTCHA
verification, then controller. OTP verification decrypts before its
controller.

## Key setup

Configure these server environment variables:

```text
ENCRYPTION_KEY_ID=rsa-2026-01
ENCRYPTION_PRIVATE_KEY=<private RSA PEM>
```

The private key may use actual newlines or escaped `\\n` sequences. Store it
only in a deployment secret or protected server-side key store; never commit
it or send it to the frontend. The backend derives the public key from this
private key. Missing or invalid settings prevent server startup.

This simplified configuration supports **one key at a time**. It does not
accept requests encrypted with a previous key during rotation. The public-key
endpoint uses `Cache-Control: no-store` to avoid clients reusing a stale key,
but rotation still requires a coordinated deployment and may reject in-flight
requests encrypted with the prior key. Add retained-key lookup before using
overlapping key rotation in production.

## Code map

- `src/config/encryption.config.js`: loads the single private key, validates
  its type and size, and derives its public key.
- `src/controllers/encryption.controller.js` and
  `src/routes/encryption.route.js`: publish the key ID and public key.
- `src/middleware/decryptRequest.middleware.js`: validates/decrypts encrypted
  request bodies and populates `req.body` only after GCM authentication.
- `src/routes/auth.route.ts`: applies decryption to login and OTP verification.
- `index.js`: mounts routes and sets a bounded JSON body limit.
- `client/src/encryption.js`: encrypts request bodies using browser Web Crypto.
- `client/src/App.jsx`: sends both auth POST requests through the helper.

The frontend is React/Vite, not React Native. Browser Web Crypto requires a
secure context: HTTPS in deployment (localhost is treated as secure by browsers).

## Rejection behavior and checks

The middleware requires exactly the five envelope fields, validates Base64 and
decoded lengths, checks the key ID and 32-byte AES key, authenticates the GCM
tag, requires valid UTF-8 JSON, and accepts only a top-level object. Invalid
requests receive a generic `400 Invalid encrypted request` response. The
ciphertext limit is 1 MiB; Express JSON parsing allows up to 2 MiB for Base64
overhead.

Tests cover valid Node and browser-generated envelopes, altered GCM tags,
unknown key IDs, and malformed envelopes. Do not log plaintext bodies,
credentials, AES keys, or private key material.
