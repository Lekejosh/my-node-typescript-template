import response from "../utils/response";
import AuthService from "../services/auth.service";

import type { Request, Response } from "express";

class AuthController {
    async register(req: Request, res: Response) {
        const result = await AuthService.register(req.body);
        const thirtyDaysInSeconds = 30 * 24 * 60 * 60;
        const expires = new Date(Date.now() + thirtyDaysInSeconds * 1000);
        res.cookie("refreshToken", result.refreshToken, {
            expires,
            httpOnly: true
        });
        const data = {
            user: result.user,
            accessToken: result.token
        };
        res.status(201).send(response("new user registered successfully", data));
    }

    async login(req: Request, res: Response) {
        const result = await AuthService.login(req.body);
        const thirtyDaysInSeconds = 30 * 24 * 60 * 60;
        const expires = new Date(Date.now() + thirtyDaysInSeconds * 1000);
        res.cookie("refreshToken", result.refreshToken, {
            expires,
            httpOnly: true
        });
        const data = {
            user: result.user,
            accessToken: result.token
        };
        res.status(200).send(response("user login successful", data));
    }

    async refreshAccessToken(req: Request, res: Response) {
        const result = await AuthService.refreshAccessToken(req.cookies);
        const OneDayInSeconds = 1 * 24 * 60 * 60;
        const expires = new Date(Date.now() + OneDayInSeconds * 1000);

        res.clearCookie("refreshToken");

        res.cookie("refreshToken", result.refreshTokenJWTNew, {
            expires,
            httpOnly: true
        });

        const data = {
            accessToken: result.accessToken
        };

        res.status(200).send(response("access token refreshed successfully", data));
    }

    async logout(req: Request, res: Response) {
        const result = await AuthService.logout(req.cookies);

        res.clearCookie("refreshToken");
        res.status(200).send(response("user logout successful", result));
    }

    async verifyEmail(req: Request, res: Response) {
        const result = await AuthService.verifyEmail(req.body, req.$user._id);
        res.status(200).send(response("email verified successfully", result));
    }

    async requestEmailVerification(req: Request, res: Response) {
        const result = await AuthService.requestEmailVerification(req.$user._id);
        res.status(200).send(response("email verification link sent", result));
    }

    async requestPasswordReset(req: Request, res: Response) {
        const result = await AuthService.requestPasswordReset(req.query.email as string);
        res.status(200).send(response("password reset link sent", result));
    }

    async resetPassword(req: Request, res: Response) {
        const result = await AuthService.resetPassword(req.body);
        res.status(200).send(response("password updated", result));
    }

    async updatePassword(req: Request, res: Response) {
        const result = await AuthService.updatePassword(req.$user._id, req.body);
        res.status(200).send(response("password updated", result));
    }
}

export default new AuthController();
