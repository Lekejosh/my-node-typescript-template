import JWT from "jsonwebtoken";
import User from "../models/user.model";

import CustomError from "@leke_josh/modules/build/utils/custom-error";
import type { Request, Response, NextFunction } from "express";
import { GenerateTokenInput } from "../types/auth";
const { JWT_SECRET } = process.env;

/**
 * If no role is passed the default role is user
 *
 * @param  {any[]} roles List of roles allowed to access the route
 */
const auth = (roles: string[] = []) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        if (!req.headers.authorization) throw new CustomError("unauthorized access: Token not found", 401);
        const token = req.headers.authorization.split(" ")[1];
        const decoded = JWT.verify(token, JWT_SECRET!) as GenerateTokenInput;
        const user = await User.findById(decoded.userId);

        if (!user) throw new CustomError("unauthorized access: User does not exist", 401);

        if (!user.isVerified) throw new CustomError("unauthorized access: Please verify email address", 401);

        if (!roles.includes(user.role)) throw new CustomError("unauthorized access", 401);

        req.$user = user;

        next();
    };
};

export default auth;
