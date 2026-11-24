import { createHash, randomBytes } from "node:crypto";
import db from "../config/db.js";

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function checkDevice(req, res) {
    const deviceUuid = req.body?.device_uuid;

    if (typeof deviceUuid !== "string" || !uuidPattern.test(deviceUuid)) {
        return res.status(400).json({ success: false, message: "Valid device_uuid is required." });
    }

    try {
        const { rows } = await db.query(
            `SELECT d.id, d.status AS device_status, ud.status AS association_status
             FROM device_info d
             LEFT JOIN user_devices ud ON ud.device_id = d.id AND ud.user_id = $1
             WHERE d.device_uuid = $2`,
            [req.user.id, deviceUuid],
        );
        const device = rows[0];

        if (!device) {
            return res.status(200).json({ success: true, status: "NEW_DEVICE" });
        }
        if (device.device_status !== "active") {
            return res.status(403).json({ success: false, status: "DEVICE_BLOCKED" });
        }
        if (device.association_status === null) {
            return res.status(200).json({ success: true, status: "NEW_USER_ON_REGISTERED_DEVICE" });
        }
        if (device.association_status !== "active") {
            return res.status(403).json({ success: false, status: "ASSOCIATION_BLOCKED" });
        }

        return res.status(200).json({ success: true, status: "REGISTERED" });
    } catch (error) {
        console.error("Device check failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not check device." });
    }
};

// Device register karo, phir pending (temp) session ko final (active) session banao.
// Token: pending session ka hona chahiye (requireDeviceAuth ye check kar chuka hai).
export async function registerDevice(req, res) {
    const deviceUuid = req.body?.device_uuid;

    if (typeof deviceUuid !== "string" || !uuidPattern.test(deviceUuid)) {
        return res.status(400).json({ success: false, message: "Valid device_uuid is required." });
    }

    // Sirf temp (pending) session hi complete ho sakta hai
    if (req.user.sessionStatus !== "pending") {
        return res.status(409).json({ success: false, message: "Session is already active." });
    }

    let client;

    try {
        client = await db.connect();
        await client.query("BEGIN");

        // 1. Device ko save karo (pehle se ho toh wahi row wapas aayegi)
        const device = await client.query(
            `INSERT INTO device_info (device_uuid)
             VALUES ($1)
             ON CONFLICT (device_uuid) DO UPDATE SET device_uuid = EXCLUDED.device_uuid
             RETURNING id, status, (xmax = 0) AS is_new`,
            [deviceUuid],
        );

        // Blocked device ko register mat karo
        if (device.rows[0].status !== "active") {
            await client.query("ROLLBACK");
            return res.status(403).json({ success: false, status: "DEVICE_BLOCKED" });
        }

        // 2. User aur device ko jodo
        const link = await client.query(
            `INSERT INTO user_devices (user_id, device_id)
             VALUES ($1, $2)
             ON CONFLICT (user_id, device_id) DO UPDATE SET user_id = EXCLUDED.user_id
             RETURNING status, (xmax = 0) AS is_new`,
            [req.user.id, device.rows[0].id],
        );

        // Is user ka link blocked ho toh bhi roko
        if (link.rows[0].status !== "active") {
            await client.query("ROLLBACK");
            return res.status(403).json({ success: false, status: "ASSOCIATION_BLOCKED" });
        }

        const deviceStatus = device.rows[0].is_new
            ? "NEW_DEVICE"
            : link.rows[0].is_new ? "NEW_USER_ON_REGISTERED_DEVICE" : "REGISTERED";

        // 3. Naya final token banao aur wahi session row active karo, device se bandho
        const accessToken = randomBytes(32).toString("base64url");
        const tokenHash = createHash("sha256").update(accessToken).digest("hex");

        const activated = await client.query(
            `UPDATE auth_sessions
             SET status = 'active',
                 device_id = $1,
                 token_hash = $2,
                 expires_at = NOW() + INTERVAL '24 hours'
             WHERE id = $3 AND user_id = $4 AND status = 'pending'
               AND revoked_at IS NULL AND expires_at > NOW()`,
            [device.rows[0].id, tokenHash, req.user.sessionId, req.user.id],
        );

        if (activated.rowCount !== 1) {
            await client.query("ROLLBACK");
            return res.status(401).json({ success: false, message: "Invalid or expired token." });
        }

        await client.query("COMMIT");
        console.log("[device] registered:", deviceStatus, "session", req.user.sessionId);

        return res.status(200).json({
            success: true,
            message: "Device registered. Login complete.",
            deviceStatus,
            sessionId: req.user.sessionId,
            sessionStatus: "active",
            accessToken,
            tokenType: "Bearer",
            expiresIn: 86400,
        });
    } catch (error) {
        if (client) {
            await client.query("ROLLBACK").catch(() => {});
        }
        console.error("Device register failed:", error.message);
        return res.status(500).json({ success: false, message: "Could not register device." });
    } finally {
        client?.release();
    }
}