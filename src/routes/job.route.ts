import { Router } from "express";
import Job from "./../controllers/job.controller";

const router = Router();

router.get("/", Job.getRunningJobs);

router.get("/:id", Job.getRunningJobsById);

export default router;
