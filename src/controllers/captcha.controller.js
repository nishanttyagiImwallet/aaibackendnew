import crypto from  "node:crypto";
import db from "../config/db.js";
import { hashCaptchaAnswer } from "../utils/captcha.js";

export async function generateCaptcha(req, res) {
    try {
        const a = crypto.randomInt(1, 20);
        const b = crypto.randomInt(1, 20);
        const answer = a + b;
        const captchaId = crypto.randomUUID();

        await db.query(
            `INSERT INTO captcha_challenges
             (id, answer_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '2 minutes')`,
            [captchaId, hashCaptchaAnswer(answer)]
        );
        res.status(200).json({
            success: true,
            captchaId,
            question: `${a}+${b}=?`
        });
    } catch (error) {
        console.error("CAPTCHA generation failed:", error.message);
        return res.status(500).json({
            success: false,
            message: "Unable to generate CAPTCHA"
        });
    }
}
