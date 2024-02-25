import { response } from "@leke_josh/modules";
import AdminService from "../services/admin.service";

import type { Request, Response } from "express";

class UserController {
    async create(req: Request, res: Response) {
        const result = await AdminService.create(req.body);
        res.status(201).send(response("User created", result));
    }

    async getAll(req: Request, res: Response) {
        const result = await AdminService.getAll(req.query);
        res.status(200).send(response("all users", result));
    }

    async getOne(req: Request, res: Response) {
        const result = await AdminService.getOne(req.params.userId);
        res.status(200).send(response("user data", result));
    }

    async delete(req: Request, res: Response) {
        await AdminService.delete(req.params.userId);
        res.status(204).end();
    }
}

export default new UserController();
