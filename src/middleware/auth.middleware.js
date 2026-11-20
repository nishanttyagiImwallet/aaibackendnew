import { createHash } from "node:crypto";
import db from "../config/db.js";

export async function requireAuth(req, res, next) {
    const header = req.get("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

    if (!token) {
        return res.status(401).json({ success: false, message: "Bearer token is required." });
    }

    try {
        const tokenHash = createHash("sha256").update(token).digest("hex");
        const { rows } = await db.query(
            `SELECT s.user_id
             FROM auth_sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1
               AND s.revoked_at IS NULL
               AND s.expires_at > NOW()
               AND u.status = 'active'`,
            [tokenHash],
        );

        if (!rows[0]) {
            return res.status(401).json({ success: false, message: "Invalid or expired token." });
        }

        req.user = { id: rows[0].user_id };
        return next();
    } catch (error) {
        console.error("Authentication failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not authenticate request." });
    }
}
