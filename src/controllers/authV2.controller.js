import { createHash, randomBytes, randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import db from "../config/db.js";

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const devOtp = process.env.DEV_OTP_CODE ?? "123456";

// latitude/longitude: dono nahi diye -> null (theek hai). Ek diya ya galat -> "invalid".
function parseLocation(latitude, longitude) {
    if (latitude === undefined && longitude === undefined) return null;
    if (latitude === null && longitude === null) return null;

    if (typeof latitude !== "number" || typeof longitude !== "number") return "invalid";
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return "invalid";
    if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) return "invalid";

    // DB column NUMERIC(9,6): 6 decimal tak
    return { latitude: Number(latitude.toFixed(6)), longitude: Number(longitude.toFixed(6)) };
}

// v2 login: AUTO SIGNUP. Email users mein nahi hai toh naya user "pending" banta hai,
// aur OTP bhejte hain. Pehla sahi OTP hi signup hai (verifyOtpV2 user ko "active" karta hai).
export async function loginV2(req, res) {
    const email = typeof req.body?.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";

    if (!emailPattern.test(email)) {
        return res.status(400).json({ success: false, message: "Valid email is required." });
    }

    // Development only (v1 jaisa)
    if (process.env.NODE_ENV === "production") {
        return res.status(503).json({ success: false, message: "OTP delivery is not configured." });
    }

    try {
        // Purane adhoore (pending) users ki safai: 1 din se purane, jinhone OTP verify nahi kiya
        await db.query(`DELETE FROM users WHERE status = 'pending' AND created_at < NOW() - INTERVAL '1 day'`);

        // Naya email ho toh pending user banao (pehle se ho toh kuch nahi hota)
        await db.query(
            `INSERT INTO users (email, status) VALUES ($1, 'pending') ON CONFLICT DO NOTHING`,
            [email]
        );

        const { rows } = await db.query(
            `SELECT id FROM users WHERE LOWER(email) = $1 AND status IN ('active', 'pending')`,
            [email]
        );

        // Blocked user: OTP nahi, lekin jawab wahi (koi pata na laga sake)
        if (rows.length === 0) {
            return res.status(202).json({ success: true, message: "OTP sent if the email is valid." });
        }

        const otpHash = await bcrypt.hash(devOtp, 10);

        await db.query(
            `INSERT INTO login_otps
             (user_id, otp_hash, created_at, expires_at, attempts, consumed_at)
             VALUES ($1, $2, NOW(), NOW() + INTERVAL '5 minutes', 0, NULL)
             ON CONFLICT (user_id)
             DO UPDATE SET
                otp_hash = EXCLUDED.otp_hash,
                created_at = NOW(),
                expires_at = EXCLUDED.expires_at,
                attempts = 0,
                consumed_at = NULL`,
            [rows[0].id, otpHash]
        );

        return res.status(202).json({ success: true, message: "OTP sent if the email is valid.", devOtp });
    } catch (error) {
        console.error("Login (v2) failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not start login." });
    }
}

// v2 verify-otp: OTP sahi hote hi SEEDHA login (active session).
// Device pehle se verify hai (requireDeviceToken ne req.device set kiya),
// isliye session isi device se bandh jata hai. Pending/temp token ki zaroorat nahi.


export async function verifyOtpV2(req, res) {
    const email = typeof req.body?.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";
    const otp = req.body?.otp;

    if (!emailPattern.test(email) || !/^\d{6}$/.test(otp || "")) {
        return res.status(400).json({ success: false, message: "Invalid email or OTP." });
    }

    // Development only (v1 jaisa)
    if (process.env.NODE_ENV === "production") {
        return res.status(503).json({ success: false, message: "OTP verification is not configured." });
    }

    // Location optional hai (user ijazat na de toh khaali). Hai toh dono, aur range ke andar.
    // Ye client ki bheji baat hai: sirf record ke liye, kisi faisle ke liye nahi.
    const location = parseLocation(req.body?.latitude, req.body?.longitude);

    if (location === "invalid") {
        return res.status(400).json({ success: false, message: "Invalid location." });
    }

    let client;

    try {
        client = await db.connect();
        await client.query("BEGIN");

        const { rows } = await client.query(
            `SELECT u.id, u.email, u.status AS user_status, o.otp_hash, o.attempts, o.expires_at, o.consumed_at
             FROM users u
             JOIN login_otps o ON o.user_id = u.id
             WHERE LOWER(u.email) = $1
             AND u.status IN ('active', 'pending')
             FOR UPDATE OF o`,
            [email]
        );
        const user = rows[0];

        if (
            !user ||
            user.consumed_at ||
            new Date(user.expires_at) <= new Date() ||
            user.attempts >= 5
        ) {
            await client.query("ROLLBACK");
            return res.status(401).json({ success: false, message: "Invalid or expired OTP." });
        }

        // 1. OTP check
        const isValid = await bcrypt.compare(otp, user.otp_hash);

        if (!isValid) {
            await client.query(`UPDATE login_otps SET attempts = attempts + 1 WHERE user_id = $1`, [user.id]);
            await client.query("COMMIT");
            return res.status(401).json({ success: false, message: "Invalid or expired OTP." });
        }

        // 2. User ko is device se jodo (pehli baar ho toh nayi row)
        const link = await client.query(
            `INSERT INTO user_devices (user_id, device_id)
             VALUES ($1, $2)
             ON CONFLICT (user_id, device_id) DO UPDATE SET user_id = EXCLUDED.user_id
             RETURNING status, (xmax = 0) AS is_new`,
            [user.id, req.device.id]
        );
    
        if (link.rows[0].status !== "active") {
            await client.query("ROLLBACK");
            return res.status(403).json({ success: false, status: "ASSOCIATION_BLOCKED" });
        }

        const deviceStatus = link.rows[0].is_new ? "NEW_USER_ON_REGISTERED_DEVICE" : "REGISTERED";

        // 3. OTP ko "used" mark karo
        const consumed = await client.query(
            `UPDATE login_otps
             SET consumed_at = NOW()
             WHERE user_id = $1
             AND consumed_at IS NULL
             AND expires_at > NOW()
             AND attempts < 5`,
            [user.id]
        );

        if (consumed.rowCount !== 1) {
            await client.query("ROLLBACK");
            return res.status(401).json({ success: false, message: "Invalid or expired OTP." });
        }

        // 4a. Naya (pending) user: OTP sahi hua, matlab email verify ho gaya. Ab user ACTIVE.
        const isNewUser = user.user_status === "pending";

        if (isNewUser) {
            await client.query(`UPDATE users SET status = 'active' WHERE id = $1 AND status = 'pending'`, [user.id]);
        }

        // 4b. SESSION: seedha active, isi device se bandha (device_id = device token wala device)
        const sessionId = randomUUID();
        const accessToken = randomBytes(32).toString("base64url");
        const tokenHash = createHash("sha256").update(accessToken).digest("hex");
// 
        await client.query(
            `INSERT INTO auth_sessions
               (id, user_id, token_hash, expires_at, status, device_id, ip_address, latitude, longitude)
             VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours', 'active', $4, $5, $6, $7)`,
            [
                sessionId, user.id, tokenHash, req.device.id,
                req.ip ?? null,                       // login ki IP
                location?.latitude ?? null,
                location?.longitude ?? null
            ]
        );
        await client.query("COMMIT");
//  naya user hai ,already registered hai kya yaha apr
        return res.status(200).json({
            success: true,
            message: "Login successful.",
            user: { id: user.id, email: user.email },
            isNewUser,
            deviceStatus,
            sessionId,
            sessionStatus: "active",
            accessToken,
            tokenType: "Bearer",
            expiresIn: 86400
        });
    } catch (error) {
        if (client) {
            await client.query("ROLLBACK").catch(() => {});
        }
        console.error("OTP verification (v2) failed:", error.message);
        return res.status(500).json({ success: false, message: "Server error." });
    } finally {
        client?.release();
    }
}
