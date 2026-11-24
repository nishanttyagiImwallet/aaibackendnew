const PUBLIC_KEY_URL = "/api/v1/encryption/public-key";
const AUTH_TAG_BYTES = 16;
// buffer to Base64. 
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000;
    let binary = "";

    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }

    return btoa(binary);
}

// PEM text  →  header/footer aur spaces hatao  →  Base64 check karo
    //       →  atob se decode karo  →  bytes array (DER)
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
// public key(taale) ko lene. frontend se api ka through
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
        // public key ko  bass64  se bytes  mai change kiya.
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
// payload is changed to string  here
    const serialized = JSON.stringify(payload);
    if (typeof serialized !== "string") {
        throw new Error("Request body must be JSON serializable.");
    }
    const { keyId, publicKey } = await fetchEncryptionKey();

    // ase key generate hua hai global object se
    const aesKey = await globalThis.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt"]
    );

    // ase key ko bytes mai change karo bhai yaha par.rsa  mai store karne ke liye bhai
    const aesKeyBytes = new Uint8Array(
        await globalThis.crypto.subtle.exportKey("raw", aesKey)
    );
    // random value for salt.
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    // string ko bytes mai change karna bhai.
    const plaintext = new TextEncoder().encode(serialized);
// encrypt  the bytes payload with salt and text payload with some bytes
    const encryptedWithTag = new Uint8Array(
        await globalThis.crypto.subtle.encrypt(
            { name: "AES-GCM", iv, tagLength: AUTH_TAG_BYTES * 8 },
            aesKey,
            plaintext
        )
    );
    // tag ki length encryption se badi hai bhai yaha par.
    if (encryptedWithTag.length <= AUTH_TAG_BYTES) {
        aesKeyBytes.fill(0);
        throw new Error("Could not encrypt the request body.");
    }
// shuru se lekar (total - 16) tak = lock hua data
    const ciphertext = encryptedWithTag.subarray(
        0,
        encryptedWithTag.length - AUTH_TAG_BYTES
    );
// aakhri 16 bytes = seal
    const authTag = encryptedWithTag.subarray(
        encryptedWithTag.length - AUTH_TAG_BYTES
    );

 // key ko taale mai rakha hai yaha par bhai
//  AseKeywithBytes add ki hai bhai yaha par.

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
