import { Router } from "express";

import { ROLE } from "./../config";
import auth from "./../middlewares/auth.middleware";
import UserCtrl from "./../controllers/user.controller";
import upload from "../utils/multer";

const router = Router();

router.get("/me", auth(ROLE.USER), UserCtrl.getMe);

router.put("/me", auth(ROLE.USER),upload.single("image"), UserCtrl.updateMe);

export default router;
