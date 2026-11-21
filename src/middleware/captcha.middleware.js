import crypto from "node:crypto";
import db from "../config/db.js";
import { hashCaptchaAnswer } from "../utils/captcha.js";

export async function verifyCaptcha(req, res, next) {
    try {
        const { captchaId, captchaAnswer } = req.body ?? {};

        if (!captchaId || captchaAnswer === undefined) {
            return res.status(400).json({
                success: false,
                message: "CAPTCHA is required"
            });
        }

        if (!/^\d{1,2}$/.test(String(captchaAnswer))) {
            return res.status(400).json({
                success: false,
                message: "Invalid CAPTCHA answer"
            });
        }

        const result = await db.query(
            `SELECT * FROM captcha_challenges
             WHERE id = $1 AND expires_at > NOW()
             LIMIT 1`,
            [captchaId]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: "CAPTCHA expired or invalid"
            });
        }

        const captcha = result.rows[0];
        if (captcha.attempts >= 3) {
            return res.status(403).json({
                success: false,
                message: "CAPTCHA attempts exceeded"
            });
        }

        const expected = Buffer.from(captcha.answer_hash, "hex");
        const submitted = Buffer.from(hashCaptchaAnswer(captchaAnswer), "hex");
        const isValid = expected.length === submitted.length &&
            crypto.timingSafeEqual(expected, submitted);

        if (!isValid) {
            await db.query(
                `UPDATE captcha_challenges
                 SET attempts = attempts + 1
                 WHERE id = $1 AND attempts < 3`,
                [captchaId]
            );

            return res.status(400).json({
                success: false,
                message: "Incorrect CAPTCHA answer"
            });
        }

        await db.query(
            `DELETE FROM captcha_challenges
             WHERE id = $1`,
            [captchaId]
        );

        return next();
    } catch (error) {
        console.error("CAPTCHA verification failed:", error.message);
        return res.status(500).json({
            success: false,
            message: "Could not verify CAPTCHA"
        });
    }
}
