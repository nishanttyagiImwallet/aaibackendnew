import { useEffect, useState } from "react";
import { encryptRequestBody } from "./encryption.js";
import { getDeviceInfo, getDeviceUuid } from "./device.js";
import "./App.css";

const digitsOnly = (value, max) => value.replace(/\D/g, "").slice(0, max);

// Server ko request bhejo aur JSON jawab wapas do. Kuch galat ho toh error throw.
async function requestJson(path, options) {
    let response, data;

    try {
        response = await fetch(path, options);
    } catch {
        throw new Error("Cannot reach the API. Make sure the backend is running.");
    }

    try {
        data = await response.json();
    } catch {
        throw new Error("The server returned an invalid response.");
    }

    if (!response.ok || data.success === false) {
        throw new Error(data.message || `Request failed (${response.status}).`);
    }

    return data;
}

// POST ki body hamesha encrypt hokar jaati hai
async function postJson(path, payload) {
    return requestJson(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(await encryptRequestBody(payload))
    });
}

async function fetchCaptcha() {
    const result = await requestJson("/api/v1/auth/captcha");

    if (!result.captchaId || !result.question) {
        throw new Error("The server returned an invalid CAPTCHA.");
    }

    return { id: result.captchaId, question: result.question };
}

function App() {
    const [email, setEmail] = useState("");
    const [otp, setOtp] = useState("");
    const [captcha, setCaptcha] = useState(null);
    const [captchaAnswer, setCaptchaAnswer] = useState("");
    const [captchaLoading, setCaptchaLoading] = useState(true);
    const [step, setStep] = useState("email");
    const [developmentOtp, setDevelopmentOtp] = useState("");
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);
    const [user, setUser] = useState(null);

    // Naya CAPTCHA lao ("Refresh" dabane par, ya galti ke baad)
    async function loadCaptcha() {
        setCaptchaLoading(true);

        try {
            setCaptcha(await fetchCaptcha());
            setCaptchaAnswer("");
        } catch (captchaError) {
            setCaptcha(null);
            setError(captchaError.message);
        } finally {
            setCaptchaLoading(false);
        }
    }

    // Page khulte hi pehla CAPTCHA lao
    useEffect(() => {
        fetchCaptcha()
            .then(setCaptcha)
            .catch((captchaError) => setError(captchaError.message))
            .finally(() => setCaptchaLoading(false));
    }, []);

    // Dono forms submit hone par yahi shuru mein chalta hai
    function startRequest(event) {
        event.preventDefault();
        setLoading(true);
        setError("");
        setMessage("");
    }

    async function requestOtp(event) {
        startRequest(event);

        try {
            const result = await postJson("/api/v1/auth/login", {
                email,
                captchaId: captcha.id,
                captchaAnswer
            });
            const devOtp = result.devOtp ?? "";

            setDevelopmentOtp(devOtp);
            setOtp(devOtp);
            setCaptcha(null);
            setStep("otp");
            setMessage(
                devOtp
                    ? `Development OTP: ${devOtp}`
                    : "If the account exists, an OTP has been created."
            );
        } catch (requestError) {
            setError(requestError.message);
            await loadCaptcha(); // CAPTCHA ek hi baar chalta hai, naya lao
        } finally {
            setLoading(false);
        }
    }

    async function verifyOtp(event) {
        startRequest(event);

        try {
            // OTP ke saath device ki pehchaan bhi jaati hai (encrypted body ke andar)
            const result = await postJson("/api/v1/auth/verify-otp", {
                email,
                otp,
                device_uuid: getDeviceUuid(),
                device_info: getDeviceInfo()
            });
            setUser({ ...result.user, accessToken: result.accessToken });
        } catch (requestError) {
            setError(requestError.message);
        } finally {
            setLoading(false);
        }
    }

    function changeEmail() {
        setStep("email");
        setOtp("");
        setDevelopmentOtp("");
        setError("");
        setMessage("");
        loadCaptcha();
    }

    if (user) {
        return (
            <main className="login-page">
                <section className="login-card" aria-live="polite">
                    <h1>Signed in</h1>
                    <p>You are signed in as {user.email}.</p>
                </section>
            </main>
        );
    }

    return (
        <main className="login-page">
            <section className="login-card">
                <h1>Sign in</h1>
                <p className="subtitle">Sign in with your email and a one-time code.</p>

                {step === "email" ? (
                    <form onSubmit={requestOtp}>
                        <label htmlFor="email">Email</label>
                        <input
                            id="email"
                            type="email"
                            autoComplete="email"
                            value={email}
                            onChange={(event) => setEmail(event.target.value)}
                            placeholder="you@example.com"
                            required
                        />
                        <div className="captcha-question">
                            <span>{captchaLoading ? "Loading CAPTCHA…" : captcha?.question || "CAPTCHA unavailable"}</span>
                            <button
                                className="refresh-captcha"
                                type="button"
                                onClick={loadCaptcha}
                                disabled={loading || captchaLoading}
                            >
                                Refresh
                            </button>
                        </div>
                        <label htmlFor="captchaAnswer">CAPTCHA answer</label>
                        <input
                            id="captchaAnswer"
                            type="text"
                            inputMode="numeric"
                            value={captchaAnswer}
                            onChange={(event) => setCaptchaAnswer(digitsOnly(event.target.value, 2))}
                            placeholder="Enter the answer"
                            pattern="[0-9]{1,2}"
                            maxLength={2}
                            disabled={!captcha || captchaLoading}
                            required
                        />
                        <button type="submit" disabled={loading || captchaLoading || !captcha}>
                            {loading ? "Sending…" : "Continue"}
                        </button>
                    </form>
                ) : (
                    <form onSubmit={verifyOtp}>
                        <p className="email-summary">
                            Enter the code for <strong>{email}</strong>
                        </p>
                        <label htmlFor="otp">One-time code</label>
                        <input
                            id="otp"
                            type="text"
                            inputMode="numeric"
                            autoComplete="one-time-code"
                            value={otp}
                            onChange={(event) => setOtp(digitsOnly(event.target.value, 6))}
                            placeholder="6-digit code"
                            maxLength={6}
                            pattern="[0-9]{6}"
                            required
                        />
                        <button type="submit" disabled={loading}>
                            {loading ? "Verifying…" : "Verify and sign in"}
                        </button>
                        <button className="secondary-button" type="button" onClick={changeEmail}>
                            Use a different email
                        </button>
                    </form>
                )}

                {error && <p className="error" role="alert">{error}</p>}
                {message && (
                    <p className={developmentOtp ? "notice development-otp" : "notice"} role="status">
                        {message}
                    </p>
                )}
            </section>
        </main>
    );
}

export default App;
