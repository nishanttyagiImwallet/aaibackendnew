import { createHash, randomBytes, randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import db from "../config/db.js";

const devOtp = process.env.DEV_OTP_CODE ?? "123456";
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


export async function login(req, res) {
    const email = typeof req.body?.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";

    // 1. Validate email
    if (!emailPattern.test(email || "")) {
        return res.status(400).json({
            success: false,
            message: "Valid email is required."
        });
    }

    // 2. Production check
    if (process.env.NODE_ENV === "production") {
        return res.status(503).json({
            success: false,
            message: "OTP delivery is not configured."
        });
    }

    try {
        // 3. Find user
        const { rows } = await db.query(
            `SELECT id FROM users
             WHERE LOWER(email) = $1 AND status = 'active'`,
            [email]
        );

        if (rows.length === 0) {
            return res.status(202).json({
                success: true,
                message: "If account exists, OTP was created."
            });
        }

        // 4. Generate OTP hash
        const otpHash = await bcrypt.hash(devOtp, 10);

        // 5. Save OTP in database
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

        // 6. Send response 
        return res.status(202).json({
            success: true,
            message: "OTP created successfully.",
            devOtp
        });

    } catch (error) {
        console.error("Login failed:", error);

        return res.status(500).json({
            success: false,
            message: "Could not start login."
        });
    }
}
export async function verifyOtp(req, res) {
    const email = typeof req.body?.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";
    const otp = req.body?.otp;

    // 1. Validate input
    if (!emailPattern.test(email || "") || !/^\d{6}$/.test(otp || "")) {
        return res.status(400).json({
            success: false,
            message: "Invalid email or OTP."
        });
    }

    // 2. Development only
    if (process.env.NODE_ENV === "production") {
        return res.status(503).json({
            success: false,
            message: "OTP verification is not configured."
        });
    }

    let client;

    try {
        client = await db.connect();
        await client.query("BEGIN");
        const { rows } = await client.query(
            `SELECT u.id, u.email, o.otp_hash, o.attempts, o.expires_at, o.consumed_at
             FROM users u
             JOIN login_otps o ON o.user_id = u.id
             WHERE LOWER(u.email) = $1
             AND u.status = 'active'
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
            return res.status(401).json({
                success: false,
                message: "Invalid or expired OTP."
            });
        }

        const isValid = await bcrypt.compare(otp, user.otp_hash);

        if (!isValid) {
            await client.query(
                `UPDATE login_otps
                 SET attempts = attempts + 1
                 WHERE user_id = $1`,
                [user.id]
            );
            await client.query("COMMIT");

            return res.status(401).json({
                success: false,
                message: "Invalid or expired OTP."
            });
        }

        const consumedOtp = await client.query(
            `UPDATE login_otps
             SET consumed_at = NOW()
             WHERE user_id = $1
             AND consumed_at IS NULL
             AND expires_at > NOW()
             AND attempts < 5`,
            [user.id]
        );

        if (consumedOtp.rowCount !== 1) {
            await client.query("ROLLBACK");
            return res.status(401).json({
                success: false,
                message: "Invalid or expired OTP."
            });
        }

        const sessionId = randomUUID();
        const accessToken = randomBytes(32).toString("base64url");
        const tokenHash = createHash("sha256").update(accessToken).digest("hex");

        // Temp (pending) session: sirf device check/register ke liye, 5 minute.
        // Final session device register hone ke baad banega.
        await client.query(
            `INSERT INTO auth_sessions (id, user_id, token_hash, expires_at, status)
             VALUES ($1, $2, $3, NOW() + INTERVAL '5 minutes', 'pending')`,
            [sessionId, user.id, tokenHash]
        );
        await client.query("COMMIT");

        return res.status(200).json({
            success: true,
            message: "OTP verified successfully.",
            user: {
                id: user.id,
                email: user.email
            },
            sessionId,
            sessionStatus: "pending",
            accessToken,
            tokenType: "Bearer",
            expiresIn: 300
        });

    } catch (error) {
        if (client) {
            await client.query("ROLLBACK").catch((rollbackError) => {
                console.error("OTP transaction rollback failed:", rollbackError.message);
            });
        }
        console.error("OTP verification failed:", error);

        return res.status(500).json({
            success: false,
            message: "Server error."
        });
    } finally {
        client?.release();
    }
}
