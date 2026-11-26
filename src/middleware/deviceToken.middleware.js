import { createHash } from "node:crypto";
import db from "../config/db.js";

// Guard 1: DEVICE TOKEN (limited access)
// Header: X-Device-Token: <token>   (register ya refresh se mila 30 min ka token)
// Sahi ho toh req.device = { id, uuid } set karke request aage jaane deta hai.
export async function requireDeviceToken(req, res, next) {
    // device token header se liya hai bhai. 
    const token = req.get("x-device-token") ?? "";

    if (!token) {
        return res.status(401).json({
            success: false,
            code: "DEVICE_TOKEN_REQUIRED",
            message: "Device token is required."
        });
    }

    try {
        // DB mein token ka hash save hai, isliye hash banake dhoondte hain
        const tokenHash = createHash("sha256").update(token).digest("hex");
        const { rows } = await db.query(
            `SELECT d.id, d.device_uuid
             FROM device_tokens t
             JOIN device_info d ON d.id = t.device_id
             WHERE t.token_hash = $1
               AND t.expires_at > NOW()
               AND d.status = 'active'`,
            [tokenHash],
        );

        if (!rows[0]) {
            return res.status(401).json({
                success: false,
                code: "DEVICE_TOKEN_REQUIRED",
                message: "Device token invalid or expired."
            });
        }
// device ki jankari  ko req object mai dal diya hai bhai.
        req.device = { id: rows[0].id, uuid: rows[0].device_uuid };
        return next();
    } catch (error) {
        console.error("Device token check failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not verify device." });
    }
}

// Guard 3: SAME DEVICE
// Session aur device token EK HI device ke hone chahiye.
// requireDeviceToken (req.device) aur requireAuth (req.user.deviceId) ke BAAD lagao.
// Isse chori hua session doosre phone ke device token ke saath nahi chalta.
export function sameDevice(req, res, next) {
    if (!req.user?.deviceId || req.user.deviceId !== req.device?.id) {
        return res.status(403).json({
            success: false,
            code: "DEVICE_MISMATCH",
            message: "Session does not belong to this device."
        });
    }

    return next();
}
