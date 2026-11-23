import assert from "node:assert/strict";
import {
    constants,
    createCipheriv,
    generateKeyPairSync,
    publicEncrypt,
    randomBytes
} from "node:crypto";
import test from "node:test";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048
});

process.env.ENCRYPTION_KEY_ID = "test-key";
delete process.env.ENCRYPTION_PRIVATE_KEYS_JSON;
process.env.ENCRYPTION_PRIVATE_KEY = privateKey
    .export({ format: "pem", type: "pkcs8" })
    .toString();

const { decryptRequest } = await import("../src/middleware/decryptRequest.middleware.js");
const { encryptRequestBody } = await import("../client/src/encryption.js");

function createEnvelope(body) {
    const aesKey = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
    const encryptedData = Buffer.concat([
        cipher.update(JSON.stringify(body), "utf8"),
        cipher.final()
    ]);

    return {
        keyId: "test-key",
        encryptedKey: publicEncrypt(
            {
                key: publicKey,
                padding: constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            aesKey
        ).toString("base64"),
        encryptedData: encryptedData.toString("base64"),
        iv: iv.toString("base64"),
        authTag: cipher.getAuthTag().toString("base64")
    };
}

function invokeMiddleware(body) {
    const req = { body };
    const res = {
        statusCode: null,
        responseBody: null,
        status(statusCode) {
            this.statusCode = statusCode;
            return this;
        },
        json(responseBody) {
            this.responseBody = responseBody;
            return this;
        }
    };
    let nextCalled = false;

    decryptRequest(req, res, () => {
        nextCalled = true;
    });

    return { req, res, nextCalled };
}

test("decrypts a valid AES-GCM request before calling next", () => {
    const expectedBody = {
        email: "person@example.com",
        captchaId: "captcha-id",
        captchaAnswer: "9"
    };
    const result = invokeMiddleware(createEnvelope(expectedBody));

    assert.equal(result.nextCalled, true);
    assert.equal(result.res.statusCode, null);
    assert.deepEqual(result.req.body, expectedBody);
});

test("decrypts the envelope produced by the browser encryption helper", async () => {
    const expectedBody = { email: "person@example.com", otp: "123456" };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => ({
        ok: true,
        json: async () => ({
            keyId: "test-key",
            algorithm: "RSA-OAEP-256",
            publicKey: publicKey.export({ format: "pem", type: "spki" }).toString()
        })
    });

    try {
        const envelope = await encryptRequestBody(expectedBody);
        const result = invokeMiddleware(envelope);

        assert.equal(result.nextCalled, true);
        assert.deepEqual(result.req.body, expectedBody);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test("rejects a request with an altered authentication tag", () => {
    const envelope = createEnvelope({ email: "person@example.com" });
    const tag = Buffer.from(envelope.authTag, "base64");
    tag[0] ^= 1;
    envelope.authTag = tag.toString("base64");

    const result = invokeMiddleware(envelope);

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 400);
    assert.deepEqual(result.res.responseBody, {
        success: false,
        message: "Invalid encrypted request."
    });
});

test("rejects unknown key IDs and malformed envelope fields", () => {
    const unknownKey = createEnvelope({ email: "person@example.com" });
    unknownKey.keyId = "unknown-key";

    const unknownKeyResult = invokeMiddleware(unknownKey);
    assert.equal(unknownKeyResult.nextCalled, false);
    assert.equal(unknownKeyResult.res.statusCode, 400);

    const malformedResult = invokeMiddleware({
        ...createEnvelope({ email: "person@example.com" }),
        extra: "not allowed"
    });
    assert.equal(malformedResult.nextCalled, false);
    assert.equal(malformedResult.res.statusCode, 400);
});
