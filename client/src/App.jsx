import { useEffect, useState } from "react";
import { encryptRequestBody } from "./encryption.js";
import "./App.css";

async function requestJson(path, options) {
    let response;

    try {
        response = await fetch(path, options);
    } catch {
        throw new Error("Cannot reach the API. Make sure the backend is running.");
    }

    let data;
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

function getJson(path) {
    return requestJson(path);
}

function postJson(path, payload) {
    return encryptRequestBody(payload).then((encryptedPayload) => requestJson(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(encryptedPayload)
    }));
}

function parseCaptcha(result) {
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

    async function loadCaptcha() {
        setCaptchaLoading(true);

        try {
            setCaptcha(parseCaptcha(await getJson("/api/v1/auth/captcha")));
            setCaptchaAnswer("");
        } catch (captchaError) {
            setCaptcha(null);
            setError(captchaError.message);
        } finally {
            setCaptchaLoading(false);
        }
    }

    useEffect(() => {
        let active = true;

        getJson("/api/v1/auth/captcha")
            .then((result) => {
                if (!active) return;
                setCaptcha(parseCaptcha(result));
            })
            .catch((captchaError) => {
                if (!active) return;
                setCaptcha(null);
                setError(captchaError.message);
            })
            .finally(() => {
                if (active) setCaptchaLoading(false);
            });

        return () => {
            active = false;
        };
    }, []);

    async function requestOtp(event) {
        event.preventDefault();
        setLoading(true);
        setError("");
        setMessage("");

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
            await loadCaptcha();
        } finally {
            setLoading(false);
        }
    }

    async function verifyOtp(event) {
        event.preventDefault();
        setLoading(true);
        setError("");
        setMessage("");

        try {
            const result = await postJson("/api/v1/auth/verify-otp", { email, otp });
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
        void loadCaptcha();
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
                            onChange={(event) => setCaptchaAnswer(event.target.value.replace(/\D/g, "").slice(0, 2))}
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
                            onChange={(event) => setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))}
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
