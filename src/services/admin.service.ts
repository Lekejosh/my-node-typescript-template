/* eslint-disable @typescript-eslint/no-explicit-any */
import User from "./../models/user.model";
import CustomError from "./../utils/custom-error";
import { Queue } from "bullmq";
import client from "../database/redis";

const queue = new Queue("image-upload", {
    redis: { host: "127.0.0.1", port: 6379 }
} as any);

class AdminService {
    async create(data: UserCreateInput) {
        return await new User(data).save();
    }

    async getAll(pagination: PaginationInput) {
        /* Note:
         * - if sorting in ascending order (1) then use $gt
         * - if sorting in descending order (-1) then use $lt
         */
        const { limit = 5, next } = pagination;
        let query = {};

        const total = await User.countDocuments(query);

        if (next) {
            const [nextId, nextCreatedAt] = next.split("_");
            query = {
                ...query,
                $or: [{ createdAt: { $gt: nextCreatedAt } }, { createdAt: nextCreatedAt, _id: { $gt: nextId } }]
            };
        }

        const users = await User.find(query, { password: 0, __v: 0 })
            .sort({ createdAt: 1, _id: 1 })
            .limit(Number(limit) + 1);

        const hasNext = users.length > limit;
        if (hasNext) users.pop(); // Remove the extra user from the array

        const nextCursor = hasNext ? `${users[users.length - 1]._id}_${users[users.length - 1].createdAt.getTime()}` : null;

        return {
            users,
            pagination: {
                total,
                hasNext,
                next: nextCursor
            }
        };
    }

    async getOne(userId: string) {
        const user = await User.findOne({ _id: userId }, { password: 0, __v: 0 });
        if (!user) throw new CustomError("user does not exist");

        return user;
    }

    async update(userId: string, data: UserUpdateInput, imagePath: string | undefined) {
        const user = await User.findById(userId);
        if (!user) {
            throw new CustomError("User does not exist");
        }

        if (imagePath) {
            await queue.add("image-upload", { imagePath, userId });
        }

        await user.updateOne(data);
        const updatedUser = await User.findById(userId);

        return updatedUser;
    }

    async delete(userId: string) {
        const user = await User.findByIdAndDelete({ _id: userId });
        if (!user) throw new CustomError("user does not exist");
        const redisUser = await client.get(userId);
        if (redisUser) await client.del(userId);
        const userRefreshToken = await client.get(`refresh_token-${userId}`);
        if (userRefreshToken) await client.del(`refresh_token-${userId}`);
        return user;
    }
}

export default new AdminService();
