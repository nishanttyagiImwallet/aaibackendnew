import { encryptionConfig } from "../config/encryption.config.js";

export function getPublicKey(_req, res) {
    res.set("Cache-Control", "no-store");

    return res.status(200).json({
        keyId: encryptionConfig.keyId,
        algorithm: "RSA-OAEP-256",
        publicKey: encryptionConfig.publicKey
    });
}
