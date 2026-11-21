import crypto from "node:crypto";

export function hashCaptchaAnswer(answer) {
    const secret = process.env.CAPTCHA_SECRET;

    if (!secret) {
        throw new Error("CAPTCHA_SECRET is missing");
    }

    return crypto
        .createHmac("sha256", secret)
        .update(String(answer))
        .digest("hex");
}
