import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { login, verifyOtp } from "../controllers/auth.controller.js";
import { generateCaptcha } from "../controllers/captcha.controller.js";
import {verifyCaptcha} from "../middleware/captcha.middleware.js";


const router = Router();
// import { checkIpReputation } from "../middleware/ipReputation.middleware.js";

// Keep the rate limiter first, so repeated requests don't call the provider.

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_req, res) => {
        res.status(429).json({
            success: false,
            message: "Too many login attempts. Please try again later."
        });
    }
});

router.post("/login", loginLimiter,verifyCaptcha, login);
router.post("/verify-otp", verifyOtp);
router.get("/captcha", generateCaptcha);

export default router;