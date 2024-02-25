/* eslint-disable @typescript-eslint/no-explicit-any */
import User from "./../models/user.model";
import CustomError from "@leke_josh/modules/build/utils/custom-error";

import cloudinary from "cloudinary";
import { APP_NAME } from "../config";
import { UserUpdateInput } from "../types/user";

class UserService {
    async update(userId: string, data: UserUpdateInput) {
        let user = await User.findById(userId);
        if (!user) throw new CustomError("user does not exist");

        user = await User.findByIdAndUpdate(userId, data, { new: true });
        return user;
    }
    async updateAvatar(imagePath: object | undefined, userId: string) {
        const user = await User.findById(userId);
        if (!user) throw new CustomError("user does not exist");
        if (!imagePath) throw new CustomError("Image not provided");
        const timestamp = Date.now();
        const cloudinaryOptions = {
            folder: APP_NAME,
            width: 1200,
            height: 630,
            crop: "fill",
            gravity: "center",
            quality: 70,
            timestamp: timestamp
        };
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        //@ts-ignore
        const result = await cloudinary.v2.uploader.upload(imagePath.path, {
            ...cloudinaryOptions,
            public_id: `${userId}_amage_${Date.now()}`
        });

        if (user.avatar.id) {
            await cloudinary.v2.uploader.destroy(user.avatar.id);
        }

        (user.avatar.id = result.public_id), (user.avatar.url = result.secure_url);
        await user.save();

        return true;
    }
}

export default new UserService();
