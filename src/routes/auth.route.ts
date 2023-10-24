import { Router } from "express";

import auth from "./../middlewares/auth.middleware";
import AuthCtrl from "../controllers/auth.controller";
import { ROLE } from "../config";

const router = Router();

router.post("/register", AuthCtrl.register);

router.post("/login", AuthCtrl.login);

router.get("/refresh-access-token", AuthCtrl.refreshAccessToken);

router.delete("/logout", AuthCtrl.logout);

router.put("/email", auth(ROLE.USER), AuthCtrl.verifyEmail);

router.get("/email", auth(ROLE.USER), AuthCtrl.requestEmailVerification);

router.post("/reset-password", AuthCtrl.resetPassword);

router.get("/request-password-reset", AuthCtrl.requestPasswordReset);

router.put("/password", auth(ROLE.USER), AuthCtrl.updatePassword);

export default router;
