/* eslint-disable @typescript-eslint/no-explicit-any */
import client from "../database/redis";
import User from "./../models/user.model";
import CustomError from "./../utils/custom-error";

import { Queue } from "bullmq";

const queue = new Queue("image-upload", {
    redis: { host: "127.0.0.1", port: 6379 }
} as any);

class UserService {
    async getOne(userId: string) {
        const user = await User.findOne({ _id: userId });
        if (!user) throw new CustomError("user does not exist");

        return user;
    }

    async update(userId: string, data: UserUpdateInput) {
        let user = await User.findById(userId);
        if (!user) throw new CustomError("user does not exist");

        user = await User.findByIdAndUpdate(userId, data, { new: true });
        await client.del(userId);
        await client.setEx(userId, 83000, JSON.stringify(user));
        return user;
    }
    async updateAvatar(imagePath: string | undefined, userId: string) {
        const user = await User.findById(userId);
        if (!user) {
            throw new CustomError("User does not exist");
        }
        if (!imagePath) throw new CustomError("Image not provided");
        await queue.add("image-upload", { imagePath, userId });
        return true;
    }
}

export default new UserService();
