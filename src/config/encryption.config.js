import { createPrivateKey, createPublicKey } from "node:crypto";

const keyId = process.env.ENCRYPTION_KEY_ID?.trim();
const privateKeyPem = process.env.ENCRYPTION_PRIVATE_KEY?.replace(/\\n/g, "\n");

if (!keyId || !privateKeyPem) {
    throw new Error("ENCRYPTION_KEY_ID and ENCRYPTION_PRIVATE_KEY are required.");
}

const privateKey = createPrivateKey(privateKeyPem);

if (
    privateKey.asymmetricKeyType !== "rsa" ||
    privateKey.asymmetricKeyDetails?.modulusLength < 2048
) {
    throw new Error("The encryption private key must be RSA with at least 2048 bits.");
}

const publicKey = createPublicKey(privateKey).export({
    format: "pem",
    type: "spki"
});

export const encryptionConfig = { keyId, privateKey, publicKey };
