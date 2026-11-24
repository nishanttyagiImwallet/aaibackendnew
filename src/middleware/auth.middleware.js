import { createHash } from "node:crypto";
import db from "../config/db.js";

// Token check karo. allowedStatuses batata hai kaun si session chalegi:
//   "pending" = temp token (OTP ho gaya, device check/register baaki)
//   "active"  = final session (device register ho chuka)
function authenticate(allowedStatuses) {
    return async function (req, res, next) {
        const header = req.get("authorization") ?? "";
        const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";

        if (!token) {
            return res.status(401).json({ success: false, message: "Bearer token is required." });
        }

        try {
            const tokenHash = createHash("sha256").update(token).digest("hex");
            const { rows } = await db.query(
                `SELECT s.id, s.user_id, s.status
                 FROM auth_sessions s
                 JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = $1
                   AND s.revoked_at IS NULL
                   AND s.expires_at > NOW()
                   AND s.status = ANY($2)
                   AND u.status = 'active'`,
                [tokenHash, allowedStatuses],
            );

            if (!rows[0]) {
                return res.status(401).json({ success: false, message: "Invalid or expired token." });
            }

            req.user = { id: rows[0].user_id, sessionId: rows[0].id, sessionStatus: rows[0].status };
            return next();
        } catch (error) {
            console.error("Authentication failed:", error.message);
            return res.status(500).json({ success: false, message: "Could not authenticate request." });
        }
    };
}

// Normal protected APIs: sirf final (active) session
export const requireAuth = authenticate(["active"]);

// Device check/register: temp (pending) ya final (active), dono chalenge
export const requireDeviceAuth = authenticate(["pending", "active"]);
