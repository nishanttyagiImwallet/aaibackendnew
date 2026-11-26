CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uidx
    ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS login_otps (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    otp_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS device_info (
    id BIGSERIAL PRIMARY KEY,
    device_uuid UUID NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_devices (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL REFERENCES device_info(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

-- Device binding: session ko device se bandhna.
-- status: 'pending' = temp token (device check baaki), 'active' = final session
ALTER TABLE auth_sessions
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS device_id BIGINT REFERENCES device_info(id);

-- Session ke saath login ki IP aur (optional) location. Sirf record ke liye, authorization ke liye nahi.
ALTER TABLE auth_sessions
    ADD COLUMN IF NOT EXISTS ip_address INET,
    ADD COLUMN IF NOT EXISTS latitude NUMERIC(9,6),
    ADD COLUMN IF NOT EXISTS longitude NUMERIC(9,6);

-- Device binding v2: device ki public key (refresh par nonce + signature se verify hoti hai)
ALTER TABLE device_info ADD COLUMN IF NOT EXISTS public_key TEXT;

-- Nonce: ek baar ka random number (sirf hash save hota hai)
CREATE TABLE IF NOT EXISTS device_nonces (
    nonce_hash CHAR(64) PRIMARY KEY,
    device_uuid UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

-- Device token: chhoti umar (30 min) ka token, public APIs ke liye (sirf hash save hota hai)
CREATE TABLE IF NOT EXISTS device_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    device_id BIGINT NOT NULL REFERENCES device_info(id),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS captcha_challenges (
    id UUID PRIMARY KEY,
    answer_hash TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);




-- attempts meamns how many times the user has tried to verify the OTP. If attempts exceed 5, the OTP is considered invalid and a new one must be generated.
--- cosume_at is the timestamp when the otp was sucessfully verified.
