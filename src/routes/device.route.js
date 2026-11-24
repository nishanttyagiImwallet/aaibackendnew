import { Router } from "express";
import { checkDevice, registerDevice } from "../controllers/device.controller.js";
import { requireDeviceAuth } from "../middleware/auth.middleware.js";


const router = Router();

// Temp (pending) token se bhi chalega, kyunki device check login ke beech mein hota hai
router.post("/check", requireDeviceAuth, checkDevice);

// Device register + final session. Pending (temp) token chahiye.
router.post("/register", requireDeviceAuth, registerDevice);

export default router;
