import "dotenv/config";
import express from "express";
import authRouter from "./src/routes/auth.route.ts";
import deviceRouter from "./src/routes/device.route.js";
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

app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});