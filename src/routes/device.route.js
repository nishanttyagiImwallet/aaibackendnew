import { Router } from "express";
import { checkDevice } from "../controllers/device.controller.js";
import { requireAuth } from "../middleware/auth.middleware.js";


const router = Router();

router.post("/check", requireAuth, checkDevice);

export default router;
