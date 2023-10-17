import { Router } from "express";

import { ROLE } from "./../config";
import auth from "./../middlewares/auth.middleware";
import Job from "./../controllers/job.controller";

const router = Router();

router.get("/", Job.getRunningJobs);

router.get("/:id", Job.getRunningJobsById);

export default router;
