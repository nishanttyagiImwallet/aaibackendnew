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