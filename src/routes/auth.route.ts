import { Router } from "express";

import auth from "./../middlewares/auth.middleware";
import AuthCtrl from "../controllers/auth.controller";
import { ROLE } from "../config";

const router = Router();

router.post("/register", AuthCtrl.register);

router.post("/login", AuthCtrl.login);

router.get("/refresh-access-token", AuthCtrl.refreshAccessToken);

router.delete("/logout", AuthCtrl.logout);

router.post("/verify-email", AuthCtrl.verifyEmail);

router.get("/request-email-verification", AuthCtrl.requestEmailVerification);

router.post("/reset-password", AuthCtrl.resetPassword);

router.get("/request-password-reset", AuthCtrl.requestPasswordReset);

router.post("/update-password",auth(ROLE.USER), AuthCtrl.updatePassword);

export default router;
