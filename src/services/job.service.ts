import { Queue } from "bullmq";

// Create a Redis Queue instance
const queue = new Queue("image-upload", {
    redis: { host: "localhost", port: 6379 }
} as any);

// Controller function to get all running jobs
export const getRunningJobs = async () => {
    try {
        // Get all the active jobs in the queue
        const activeJobs = await queue.getActive();

        // Extract the IDs of the active jobs
        const activeJobIds = activeJobs.map((job: any) => job.id);

        return activeJobIds;
    } catch (error) {
        // Handle errors here
        console.error("Error fetching active jobs:", error);
        throw error;
    }
};

export const getJobById = async (jobId: any) => {
    try {
        // Get the job by its ID
        const job = await queue.getJob(jobId);

        if (!job) {
            throw new Error(`Job with ID ${jobId} not found`);
        }

        // Get the job status using getState() method
        const status = await job.getState();

        // Access the progress object and stringify it
        const progress = JSON.stringify(job.progress);

        // Return the job details
        return {
            id: job.id,
            data: job.data,
            status: status,
            progress: progress
        };
    } catch (error) {
        // Handle errors here
        console.error(`Error fetching job with ID ${jobId}:`, error);
        throw error;
    }
};
