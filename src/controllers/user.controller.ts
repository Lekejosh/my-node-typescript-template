import { response } from "@leke_josh/modules";
import UserService from "../services/user.service";

import type { Request, Response } from "express";

class UserController {
    async getMe(req: Request, res: Response) {
        res.status(200).send(response("user data", req.$user));
    }

    async updateMe(req: Request, res: Response) {
        const result = await UserService.update(req.$user?.id as string, req.body);
        res.status(200).send(response("user updated", result));
    }

    async updateAvatar(req: Request, res: Response) {
        const result = await UserService.updateAvatar(req.file ? req.file : undefined, req.$user?.id as string);
        res.status(200).send(response("Avatar update", result));
    }
}

export default new UserController();
