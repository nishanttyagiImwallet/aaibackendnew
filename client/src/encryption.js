const PUBLIC_KEY_URL = "/api/v1/encryption/public-key";
const AUTH_TAG_BYTES = 16;

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000;
    let binary = "";

    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }

    return btoa(binary);
}

function pemToDer(pem) {
    if (typeof pem !== "string") {
        throw new Error("The server returned an invalid encryption public key.");
    }

    const base64 = pem
        .replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----/g, "")
        .replace(/\s/g, "");

    if (!base64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) {
        throw new Error("The server returned an invalid encryption public key.");
    }

    let binary;
    try {
        binary = atob(base64);
    } catch {
        throw new Error("The server returned an invalid encryption public key.");
    }

    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function fetchEncryptionKey() {
    let response;

    try {
        response = await fetch(PUBLIC_KEY_URL, {
            headers: { Accept: "application/json" }
        });
    } catch {
        throw new Error("Cannot reach the API encryption key endpoint.");
    }

    let result;
    try {
        result = await response.json();
    } catch {
        throw new Error("The server returned an invalid encryption key response.");
    }

    if (!response.ok) {
        throw new Error(result.message || "Could not load the server encryption key.");
    }

    if (
        result.algorithm !== "RSA-OAEP-256" ||
        typeof result.keyId !== "string" ||
        result.keyId.length === 0
    ) {
        throw new Error("The server returned an unsupported encryption key.");
    }

    try {
        const publicKey = await globalThis.crypto.subtle.importKey(
            "spki",
            pemToDer(result.publicKey),
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
        );

        return { keyId: result.keyId, publicKey };
    } catch {
        throw new Error("The server returned an invalid encryption public key.");
    }
}

export async function encryptRequestBody(payload) {
    if (
        !globalThis.crypto?.subtle ||
        typeof globalThis.crypto.getRandomValues !== "function"
    ) {
        throw new Error("This browser does not support secure request encryption.");
    }

    const serialized = JSON.stringify(payload);
    if (typeof serialized !== "string") {
        throw new Error("Request body must be JSON serializable.");
    }

    const { keyId, publicKey } = await fetchEncryptionKey();
    const aesKey = await globalThis.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt"]
    );
    const aesKeyBytes = new Uint8Array(
        await globalThis.crypto.subtle.exportKey("raw", aesKey)
    );
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(serialized);

    const encryptedWithTag = new Uint8Array(
        await globalThis.crypto.subtle.encrypt(
            { name: "AES-GCM", iv, tagLength: AUTH_TAG_BYTES * 8 },
            aesKey,
            plaintext
        )
    );

    if (encryptedWithTag.length <= AUTH_TAG_BYTES) {
        aesKeyBytes.fill(0);
        throw new Error("Could not encrypt the request body.");
    }

    const ciphertext = encryptedWithTag.subarray(
        0,
        encryptedWithTag.length - AUTH_TAG_BYTES
    );
    const authTag = encryptedWithTag.subarray(
        encryptedWithTag.length - AUTH_TAG_BYTES
    );

    let encryptedKey;
    try {
        encryptedKey = await globalThis.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            aesKeyBytes
        );
    } finally {
        aesKeyBytes.fill(0);
    }

    return {
        keyId,
        encryptedKey: arrayBufferToBase64(encryptedKey),
        encryptedData: arrayBufferToBase64(ciphertext),
        iv: arrayBufferToBase64(iv),
        authTag: arrayBufferToBase64(authTag)
    };
}
