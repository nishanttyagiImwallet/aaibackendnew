import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { loginV2, verifyOtpV2 } from "../controllers/authV2.controller.js";
import { verifyCaptcha } from "../middleware/captcha.middleware.js";
import { decryptRequest } from "../middleware/decryptRequest.middleware.js";
import { requireDeviceToken } from "../middleware/deviceToken.middleware.js";

const router = Router();

// v1 jaisa: 15 minute mein 5 login try
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req, res) => {
        res.status(429).json({ success: false, message: "Too many login attempts. Please try again later." });
    }
});

// Dono routes par pehle DEVICE TOKEN (limited access), phir encrypted body.
// Captcha: GET /api/v2/device/captcha

// Email + captcha -> OTP
router.post("/login", requireDeviceToken, loginLimiter, decryptRequest, verifyCaptcha, loginV2);

// OTP sahi -> seedha login (active session, isi device se bandha)
router.post("/verify-otp", requireDeviceToken, decryptRequest, verifyOtpV2);

export default router;
