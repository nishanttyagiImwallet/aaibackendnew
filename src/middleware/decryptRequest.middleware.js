import {
    constants,
    createDecipheriv,
    privateDecrypt
} from "node:crypto";
import { TextDecoder } from "node:util";
import { encryptionConfig } from "../config/encryption.config.js";

const MAX_CIPHERTEXT_BYTES = 1024 * 1024;
const FIELDS = ["keyId", "encryptedKey", "encryptedData", "iv", "authTag"];

function reject(res) {
    return res.status(400).json({
        success: false,
        message: "Invalid encrypted request."
    });
}

function decodeBase64(value) {
    if (typeof value !== "string" || !value) {
        throw new Error("Invalid Base64 value.");
    }

    const bytes = Buffer.from(value, "base64");

    // Reject malformed or non-standard Base64.
    if (bytes.toString("base64") !== value) {
        throw new Error("Invalid Base64 value.");
    }

    return bytes;
}

export function decryptRequest(req, res, next) {
    const envelope = req.body;

    // Check that the request has exactly the expected fields.
    if (
        !envelope ||
        typeof envelope !== "object" ||
        Array.isArray(envelope) ||
        Object.keys(envelope).length !== FIELDS.length ||
        FIELDS.some((field) => !Object.hasOwn(envelope, field))
    ) {
        return reject(res);
    }

    let body;

    try {
        if (envelope.keyId !== encryptionConfig.keyId) return reject(res);

        const encryptedKey = decodeBase64(envelope.encryptedKey);
        const encryptedData = decodeBase64(envelope.encryptedData);
        const iv = decodeBase64(envelope.iv);
        const authTag = decodeBase64(envelope.authTag);

        // Check the expected RSA, ciphertext, IV, and GCM tag lengths.
        const rsaKeyBytes = Math.ceil(
            encryptionConfig.privateKey.asymmetricKeyDetails.modulusLength / 8
        );

        if (
            encryptedKey.length !== rsaKeyBytes ||
            encryptedData.length === 0 ||
            encryptedData.length > MAX_CIPHERTEXT_BYTES ||
            iv.length !== 12 ||
            authTag.length !== 16
        ) {
            return reject(res);
        }

        // Use RSA-OAEP/SHA-256 to recover the AES key.
        const aesKey = privateDecrypt(
            {
                key: encryptionConfig.privateKey,
                padding: constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            encryptedKey
        );

        if (aesKey.length !== 32) return reject(res);

        // AES-GCM verifies the authentication tag during final().
        const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
        decipher.setAuthTag(authTag);

        const plaintext = Buffer.concat([
            decipher.update(encryptedData),
            decipher.final()
        ]);

        body = JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(plaintext)
        );

        if (!body || typeof body !== "object" || Array.isArray(body)) {
            return reject(res);
        }
    } catch {
        // Reject bad keys, invalid tags, malformed UTF-8, or invalid JSON.
        return reject(res);
    }

    // Only expose the body after decryption and authentication succeed.
    req.body = body;
    return next();
}
