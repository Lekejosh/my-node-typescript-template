import { Router } from "express";

import trimIncomingRequests from "../middlewares/trim-incoming-requests";

import AuthRoutes from "./auth.route";

import UserRoutes from "./user.route";

import AdminRoutes from "./admin.route";

import JobRoute from "./job.route";

import type { Request, Response } from "express";

const router = Router();

// Trim all incoming requests
router.use(trimIncomingRequests);

router.use("/api/v1/auth", AuthRoutes);

router.use("/api/v1/user", UserRoutes);

router.use("/api/v1/admin", AdminRoutes);

router.use("/api/v1/job", JobRoute);

router.get("/", (req: Request, res: Response) => {
    return res.status(200).json({ message: "You're not meant to be here :)" });
});

export default router;
