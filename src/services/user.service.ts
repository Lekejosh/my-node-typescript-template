import User from "./../models/user.model";
import cloudinary from "cloudinary";
import CustomError from "./../utils/custom-error";

import { Queue } from "bullmq";

const queue = new Queue("image-upload", {
  redis: { host: "127.0.0.1", port: 6379 },
} as any);

class UserService {
  async getOne(userId: string) {
    const user = await User.findOne({ _id: userId });
    if (!user) throw new CustomError("user does not exist");

    return user;
  }

  async update(userId: string, data: UserUpdateInput) {
    const user = await User.findById(userId);
    if (!user) throw new CustomError("user does not exist");
    if (data.image) {
      const imagePath = data.image;
      await queue.add("image-upload", { imagePath, userId });
    }

    if (data.name) {
      user.name = data.name;
    }

    user.save();

    return user;
  }
}

export default new UserService();
