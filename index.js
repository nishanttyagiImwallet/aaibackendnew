import "dotenv/config";
import express from "express";
import authRouter from "./src/routes/auth.route.ts";
import deviceRouter from "./src/routes/device.route.js";
import deviceV2Router from "./src/routes/deviceV2.route.js";
import authV2Router from "./src/routes/authV2.route.js";
import meV2Router from "./src/routes/meV2.route.js";
import encryptionRouter from "./src/routes/encryption.route.js";

const app = express();

app.use(express.json({ limit: "2mb" }));

app.get("/", (req, res) => {
    res.status(200).json({
        success: true,
        message: "AAI Backend is running!"
    });
});

app.use("/api/v1/auth", authRouter);
app.use("/api/v1/encryption", encryptionRouter);
app.use("/api/v1/device", deviceRouter);
app.use("/api/v2/device", deviceV2Router);
app.use("/api/v2/auth", authV2Router);
app.use("/api/v2", meV2Router);

app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});