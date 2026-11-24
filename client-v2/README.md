# Login client

This React client uses the backend's email + OTP login endpoints.

From the repository root, start the backend in one terminal:

```sh
npm run dev
```

In a second terminal, install the client dependencies once and start Vite:

```sh
npm --prefix client install
npm --prefix client run dev
```

The client proxies `/api` to `http://localhost:5001`. If your backend uses a different address, set `VITE_API_PROXY_TARGET` in `client/.env.local`.
