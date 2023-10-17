import response from "./../utils/response";
import { getJobById, getRunningJobs } from "./../services/job.service"; // Import the new controller

import type { Request, Response } from "express";

class JobController {
    async getRunningJobs(req: Request, res: Response) {
        try {
            const activeJobs = await getRunningJobs();
            res.status(200).send(response("active jobs", activeJobs));
        } catch (error) {
            console.error("Error fetching running jobs:", error);
            res.status(500).send(response("error", "Internal server error"));
        }
    }
    async getRunningJobsById(req: Request, res: Response) {
        try {
            const activeJobsId = await getJobById(req.params.id);
            res.status(200).send(response("active jobs", activeJobsId));
        } catch (error) {
            console.error("Error fetching running jobs:", error);
            res.status(500).send(response("error", "Internal server error"));
        }
    }
}

export default new JobController();
