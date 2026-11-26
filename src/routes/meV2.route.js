import { Router } from "express";
import { requireAuth } from "../middleware/auth.middleware.js";
import { requireDeviceToken, sameDevice } from "../middleware/deviceToken.middleware.js";

const router = Router();

// Pehli PROTECTED API (full access): device token + login session, dono chahiye.
// Guards: requireDeviceToken -> requireAuth -> sameDevice (session aur device token ek hi device ke)
router.get("/me", requireDeviceToken, requireAuth, sameDevice, (req, res) => {
    res.status(200).json({
        success: true,
        user: { id: req.user.id },
        device: { id: req.device.id },
        session: { id: req.user.sessionId, deviceId: req.user.deviceId }
    });
});

export default router;
