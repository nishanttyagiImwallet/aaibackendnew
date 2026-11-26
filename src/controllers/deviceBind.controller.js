import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import db from "../config/db.js";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

const NONCE_MINUTES = 2;
const DEVICE_TOKEN_MINUTES = 30;

// Device bolta hai "nonce do"
export async function bindStart(req, res) {
    // input  === uuid.
    // output === 
    const deviceUuid = req.body?.device_uuid;

    if (typeof deviceUuid !== "string" || !uuidPattern.test(deviceUuid)) {
        return res.status(400).json({ success: false, message: "Valid device_uuid is required." });
    }

    try {
        const nonce = randomBytes(32).toString("base64url");

        // Nonce ka sirf HASH save hota hai, asli nonce nahi
        await db.query(
            `INSERT INTO device_nonces (nonce_hash, device_uuid, expires_at)
             VALUES ($1, $2, NOW() + make_interval(mins => $3))`,
            [sha256(nonce), deviceUuid, NONCE_MINUTES],
        );
 
        return res.status(200).json({ success: true, nonce, expiresIn: NONCE_MINUTES * 60 });
    } catch (error) {
        console.error("Bind start failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not start device binding." });
    }
}

// Browser ka ECDSA signature "ieee-p1363" format mein hota hai (Node ka default DER hai)

function isValidSignature(publicKeyBase64, nonce, signatureBase64) {
    try {
        const key = createPublicKey({ key: Buffer.from(publicKeyBase64, "base64"), format: "der", type: "spki" });

        return verify(
            "sha256",
            Buffer.from(nonce),
            { key, dsaEncoding: "ieee-p1363" },
            Buffer.from(signatureBase64, "base64"),
        );
    } catch {
        return false;
    }
}

// Nonce ko "used" mark karo. Ek hi statement, isliye do requests ek saath aayein toh bhi ek hi jeetegi.
async function consumeNonce(nonce, deviceUuid) {
    const used = await db.query(
        `UPDATE device_nonces SET used_at = NOW()
         WHERE nonce_hash = $1 AND device_uuid = $2
           AND used_at IS NULL AND expires_at > NOW()`,
        [sha256(nonce), deviceUuid],
    );

    return used.rowCount === 1;
}

// Device ko nonce ka jawab dene par: bind karo aur device token do
// Input = DeviceUuid,nonce,signuture,public key.
// Output = Device Token,
export async function bindComplete(req, res) {

    const { device_uuid: deviceUuid, nonce, signature, publicKey } = req.body ?? {};

    if (
        typeof deviceUuid !== "string" || !uuidPattern.test(deviceUuid) ||
        typeof nonce !== "string" || typeof signature !== "string" || typeof publicKey !== "string"
    ) {
        return res.status(400).json({ success: false, message: "Invalid request." });
    }

    try {
        // 1. Nonce check
        if (!(await consumeNonce(nonce, deviceUuid))) {
            return res.status(400).json({ success: false, message: "Invalid or expired nonce." });
        }

        // 2. Signature check (request mein aayi public key se)
        if (!isValidSignature(publicKey, nonce, signature)) {
            return res.status(400).json({ success: false, message: "Invalid signature." });
        }

        // 3. Device save. Pehle se alag public key bandhi ho toh overwrite NAHI karna.
        // input == device_Id,public key,
        // output==  public key pahle se hai wo overwrite nahi hogi bahi.
        const { rows } = await db.query(
            `INSERT INTO device_info (device_uuid, public_key) VALUES ($1, $2)
             ON CONFLICT (device_uuid)
             DO UPDATE SET public_key = COALESCE(device_info.public_key, EXCLUDED.public_key)
             RETURNING id, status, public_key`,
            [deviceUuid, publicKey],
        );
        const device = rows[0];
// ye device blocked hai bhai
        if (device.status !== "active") {
            return res.status(403).json({ success: false, status: "DEVICE_BLOCKED" });
        }
 // ye device is already bound to another key here. 
        if (device.public_key !== publicKey) {
            return res.status(409).json({ success: false, message: "Device is already bound to another key." });
        }

        // 4. Device token (sirf hash DB mein jata hai). Purane expired tokens saaf.
        const deviceToken = randomBytes(32).toString("base64url");

        await db.query(`DELETE FROM device_tokens WHERE expires_at < NOW()`);
        await db.query(
            `INSERT INTO device_tokens (token_hash, device_id, expires_at)
             VALUES ($1, $2, NOW() + make_interval(mins => $3))`,
            [sha256(deviceToken), device.id, DEVICE_TOKEN_MINUTES],
        );

        return res.status(200).json({
            success: true,
            message: "Device verified.",
            deviceId: device.id,
            deviceToken,
            expiresIn: DEVICE_TOKEN_MINUTES * 60,
        });
    } catch (error) {
        console.error("Bind complete failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not bind device." });
    }
}












// ============================================================
// NAYA FLOW: nonce sirf REFRESH ke time aata hai, register mein nahi.
// ============================================================

// Public key ECDSA P-256 (SPKI, Base64) honi chahiye
function isP256PublicKey(publicKeyBase64) {
    try {
        const key = createPublicKey({ key: Buffer.from(publicKeyBase64, "base64"), format: "der", type: "spki" });

        return key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
    } catch {
        return false;
    }
}

// Naya device token banao (sirf hash DB mein jata hai). Purane expired tokens saaf.
async function issueDeviceToken(deviceId) {
    const deviceToken = randomBytes(32).toString("base64url");

    await db.query(`DELETE FROM device_tokens WHERE expires_at < NOW()`);
    await db.query(
        `INSERT INTO device_tokens (token_hash, device_id, expires_at)
         VALUES ($1, $2, NOW() + make_interval(mins => $3))`,
        [sha256(deviceToken), deviceId, DEVICE_TOKEN_MINUTES],
    );

    return deviceToken;
}



// REGISTER: device pehli baar bind hota hai. Nonce nahi. (Captcha agle step mein jodenge.)
// Input  = device_uuid, publicKey
// Output = deviceId, deviceToken (30 min)

export async function registerDeviceKey(req, res) {
    const { device_uuid: deviceUuid, publicKey } = req.body ?? {};

    if (typeof deviceUuid !== "string" || !uuidPattern.test(deviceUuid)) {
        return res.status(400).json({ success: false, message: "Valid device_uuid is required." });
    }
    if (typeof publicKey !== "string" || !isP256PublicKey(publicKey)) {
        return res.status(400).json({ success: false, message: "Valid P-256 public key is required." });
    }

    // public key bind ho gyi hai device se yaha par

    try {
        // Device save. Pehle se alag public key bandhi ho toh overwrite NAHI karna.
        const { rows } = await db.query(
            `INSERT INTO device_info (device_uuid, public_key) VALUES ($1, $2)
             ON CONFLICT (device_uuid)
             DO UPDATE SET public_key = COALESCE(device_info.public_key, EXCLUDED.public_key)
             RETURNING id, status, public_key`,
            [deviceUuid, publicKey],
        );
        const device = rows[0];
        // device  active nahi hai.
        if (device.status !== "active") {
            return res.status(403).json({ success: false, status: "DEVICE_BLOCKED" });
        }
        // device se pahle hi ek private key hai yaha par
        if (device.public_key !== publicKey) {
            return res.status(409).json({ success: false, message: "Device is already bound to another key." });
        }

        const deviceToken = await issueDeviceToken(device.id);
        return res.status(200).json({
            success: true,
            message: "Device registered.",
            deviceId: device.id,
            deviceToken,
            expiresIn: DEVICE_TOKEN_MINUTES * 60,
        });
    } catch (error) {
        console.error("Device register failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not register device." });
    }
}

// CHALLENGE: token expire hone se pehle nonce maango (sirf register ho chuke device ke liye)
// Input  = device_uuid
// Output = nonce (2 min, ek baar ka)
export async function getChallenge(req, res) {
    const deviceUuid = req.body?.device_uuid;

    if (typeof deviceUuid !== "string" || !uuidPattern.test(deviceUuid)) {
        return res.status(400).json({ success: false, message: "Valid device_uuid is required." });
    }

    try {
        // device search karta hai 
        const { rows } = await db.query(
            `SELECT status, public_key FROM device_info WHERE device_uuid = $1`,
            [deviceUuid],
        );
        const device = rows[0];

        if (!device || !device.public_key) {
            return res.status(401).json({ success: false, message: "Device is not registered." });
        }
    
        if (device.status !== "active") {
            return res.status(403).json({ success: false, status: "DEVICE_BLOCKED" });
        }

        const nonce = randomBytes(32).toString("base64url");

        await db.query(
            `INSERT INTO device_nonces (nonce_hash, device_uuid, expires_at)
             VALUES ($1, $2, NOW() + make_interval(mins => $3))`,
            [sha256(nonce), deviceUuid, NONCE_MINUTES],
        );

        return res.status(200).json({ success: true, nonce, expiresIn: NONCE_MINUTES * 60 });
    } catch (error) {
        console.error("Challenge failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not create challenge." });
    }
}

// REFRESH: nonce par signature. Signature DB mein SAVED public key se jaanchte hain
// (request mein aayi key par bharosa nahi). Sahi ho toh naya device token.
// Input  = device_uuid, nonce (challenge se mila), signature (Base64)
// Output = naya deviceToken (30 min)
export async function refreshDeviceToken(req, res) {
    const { device_uuid: deviceUuid, nonce, signature } = req.body ?? {};

    if (
        typeof deviceUuid !== "string" || !uuidPattern.test(deviceUuid) ||
        typeof nonce !== "string" || typeof signature !== "string"
    ) {
        return res.status(400).json({ success: false, message: "Invalid request." });
    }

    try {
        // 1. Nonce check (ek baar ka, isi device ka, expire nahi hua)
        if (!(await consumeNonce(nonce, deviceUuid))) {
            return res.status(400).json({ success: false, message: "Invalid or expired nonce." });
        }

        // 2. Device aur uski SAVED public key
        const { rows } = await db.query(
            `SELECT id, status, public_key FROM device_info WHERE device_uuid = $1`,
            [deviceUuid],
        );
        const device = rows[0];

        if (!device || !device.public_key) {
            return res.status(401).json({ success: false, message: "Device is not registered." });
        }
        if (device.status !== "active") {
            return res.status(403).json({ success: false, status: "DEVICE_BLOCKED" });
        }

        // 3. Signature saved key se jaancho
        if (!isValidSignature(device.public_key, nonce, signature)) {
            return res.status(401).json({ success: false, message: "Invalid signature." });
        }

        // 4. Naya token
        const deviceToken = await issueDeviceToken(device.id);

        return res.status(200).json({
            success: true,
            deviceToken,
            expiresIn: DEVICE_TOKEN_MINUTES * 60,
        });
    } catch (error) {
        console.error("Token refresh failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not refresh token." });
    }
}
