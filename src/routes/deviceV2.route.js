import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { generateCaptcha } from "../controllers/captcha.controller.js";
import {
    bindComplete,
    bindStart,
    getChallenge,
    refreshDeviceToken,
    registerDeviceKey
} from "../controllers/deviceBind.controller.js";
import { verifyCaptcha } from "../middleware/captcha.middleware.js";

const router = Router();

// Bot baar-baar nonce na maang sake
const bindLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 60,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req, res) => {
        res.status(429).json({ success: false, message: "Too many requests. Please try again later." });
    }
});

// Register kam baar hona chahiye (fake devices ki baadh rokne ke liye)
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req, res) => {
        res.status(429).json({ success: false, message: "Too many requests. Please try again later." });
    }
});

router.post("/bind/start", bindLimiter, bindStart);
router.post("/bind/complete", bindLimiter, bindComplete);

// NAYA FLOW: register mein nonce nahi, nonce sirf refresh ke liye (challenge)
// Register se pehle captcha: GET /captcha -> jawab -> POST /register { ..., captchaId, captchaAnswer }
router.get("/captcha", bindLimiter, generateCaptcha);
router.post("/register", registerLimiter, verifyCaptcha, registerDeviceKey);
router.post("/challenge", bindLimiter, getChallenge);
router.post("/refresh", bindLimiter, refreshDeviceToken);

export default router;
