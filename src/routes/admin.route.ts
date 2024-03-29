import { Router } from "express";

import { ROLE } from "./../config";
import auth from "./../middlewares/auth.middleware";
import AdminCtrl from "./../controllers/admin.controller";

const router = Router();

router.post("/", auth(ROLE.ADMIN), AdminCtrl.create);

router.get("/", auth(ROLE.ADMIN), AdminCtrl.getAll);

router.get("/:userId", auth(ROLE.ADMIN), AdminCtrl.getOne);

router.delete("/:userId", auth(ROLE.ADMIN), AdminCtrl.delete);

export default router;
