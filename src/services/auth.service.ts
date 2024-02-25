/* eslint-disable prefer-const */
/* eslint-disable @typescript-eslint/no-explicit-any */
import ms from "ms";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import JWT from "jsonwebtoken";

import User from "./../models/user.model";
import MailService from "./mail.service";
import CustomError from "@leke_josh/modules/build/utils/custom-error";
import { URL } from "../config";
import Token from "../models/token.model";
import {
    GenerateTokenInput,
    LoginInput,
    LogoutInput,
    PasswordValidator,
    RefreshTokenInput,
    ResetPasswordInput,
    UpdatePasswordInput,
    UsernameValidator,
    VerificationOne,
    VerifyEmailInput,
    refreshTokenDecode
} from "../types/auth";
import { startSession } from "mongoose";

let JWT_SECRET: string;
if (process.env.NODE_ENV === "test") {
    JWT_SECRET = "lmfao";
} else {
    JWT_SECRET = process.env.JWT_SECRET!;
}

class AuthService {
    async register(data: VerificationOne) {
        if (!data.first_name || !data.last_name || !data.email || !data.username || !data.password) throw new CustomError("Please provide all required fields");

        const session = await startSession();
        session.startTransaction();

        let user = await User.findOne({ email: data.email }).session(session);
        if (user) throw new CustomError("email already exists", 409);

        user = await User.findOne({ username: data.username }).session(session);

        const usernameTest = await this.usernameValidator({ username: data.username });

        if (!usernameTest)
            throw new CustomError(
                "Username must be 3 to 15 characters long; The acceptable special characters are: full stop, underscores and dash; you can't use only special characters as username"
            );

        if (user) throw new CustomError("Username, already taken", 409);

        if (data.phone_number) {
            user = await User.findOne({ phone_number: data.phone_number }).session(session);

            if (user) throw new CustomError("Phone number, already exist", 409);
        }

        const validate = await this.isPasswordValid({ password: data.password });

        if (!validate) {
            throw new CustomError("Password must contain at least one capital letter, one special character, one number, one small letter, and be at least 8 characters long");
        }

        user = await new User(data).save();

        await session.commitTransaction();
        session.endSession();
        if (process.env.NODE_ENV !== "test") {
            await this.requestEmailVerification(user.email);
        }
        return {
            user
        };
    }

    async login(data: LoginInput) {
        if (!data.username_or_email) throw new CustomError("Username or email is required");
        if (!data.password) throw new CustomError("password is required");
        // Check if user exist
        const user = await User.findOne({ $or: [{ email: data.username_or_email }, { username: data.username_or_email }] }).select("+password");
        if (!user) throw new CustomError("incorrect username/email and password");

        // Check if user password is correct
        const isCorrect = await bcrypt.compare(data.password, user.password);
        if (!isCorrect) throw new CustomError("incorrect username/email and password");

        const authTokens = await this.generateAuthTokens({
            userId: user.id,
            role: user.role,
            email: user.email,
            isVerified: user.isVerified
        });
        return {
            user,
            token: authTokens.accessToken,
            refreshToken: authTokens.refreshToken
        };
    }

    async generateAuthTokens(data: GenerateTokenInput) {
        const { userId, role, isVerified, email } = data;
        const accessToken = JWT.sign({ userId, role, isVerified, email }, JWT_SECRET!, { expiresIn: "1 day" });

        const refreshToken = crypto.randomBytes(32).toString("hex");
        const hash = await bcrypt.hash(refreshToken, 10);

        const refreshTokenJWT = JWT.sign({ userId, refreshToken }, JWT_SECRET!, { expiresIn: "1 day" });

        await new Token({
            userId,
            token: hash,
            type: "refresh_token",
            expiresAt: Date.now() + ms("30 days")
        }).save();

        return { accessToken, refreshToken: refreshTokenJWT };
    }

    async refreshAccessToken(data: RefreshTokenInput) {
        const { refreshToken: refreshTokenJWT } = data;

        const decoded = JWT.verify(refreshTokenJWT, JWT_SECRET!) as refreshTokenDecode;
        let { refreshToken } = decoded;
        const { userId } = decoded;

        const user = await User.findById(userId);
        if (!user) throw new CustomError("User does not exist");
        const RTokens = await Token.find({ userId, type: "refresh_token" });
        if (RTokens.length === 0) throw new CustomError("invalid or expired refresh token");

        let tokenExists = false;

        for (const token of RTokens) {
            const isValid = await bcrypt.compare(refreshToken, token.token);

            if (isValid) {
                tokenExists = true;
                break;
            }
        }

        if (!tokenExists) throw new CustomError("invalid or expired refresh token");

        const accessToken = JWT.sign({ userId, role: user.role, email: user.email, isVerified: user.isVerified }, JWT_SECRET!, {
            expiresIn: "1 day"
        });
        refreshToken = crypto.randomBytes(32).toString("hex");
        const hash = await bcrypt.hash(refreshToken, 10);

        const refreshTokenJWTNew = JWT.sign({ userId, refreshToken }, JWT_SECRET!, {
            expiresIn: "30 days"
        });

        const tokenData = {
            userId: userId,
            token: hash,
            type: "refresh_token",
            expiresAt: Date.now() + ms("30 days")
        };

        await Token.create(tokenData);

        return { accessToken, refreshTokenJWTNew };
    }

    async logout(data: LogoutInput) {
        const { refreshToken: refreshTokenJWT } = data;

        const decoded = JWT.verify(refreshTokenJWT, JWT_SECRET!) as refreshTokenDecode;
        const { refreshToken, userId } = decoded;

        const user = await User.findById(userId);
        if (!user) throw new CustomError("User does not exist");

        const RTokens = await Token.find({ userId, type: "refresh_token" });
        if (RTokens.length === 0) throw new CustomError("invalid or expired refresh token");

        let tokenExists = false;

        for (const token of RTokens) {
            const isValid = await bcrypt.compare(refreshToken, token.token);

            if (isValid) {
                tokenExists = true;
                await token.deleteOne();

                break;
            }
        }

        if (!tokenExists) throw new CustomError("invalid or expired refresh token");

        return true;
    }

    async verifyEmail(data: VerifyEmailInput) {
        const { userId, verifyToken } = data;
        if (!userId || !verifyToken) throw new CustomError("All required Data not provided");
        const user = await User.findById(userId);
        if (!user) throw new CustomError("User not found");

        if (user.isVerified) throw new CustomError("email is already verified");
        const VToken = await Token.findOne({ userId, type: "verify_email" });
        if (!VToken) throw new CustomError("invalid or expired email verification token");
        if (VToken.expiresAt < new Date(Date.now())) throw new CustomError("invalid or expired email verification token");

        const isValid = await bcrypt.compare(verifyToken, VToken.token);
        if (!isValid) throw new CustomError("invalid or expired email verification reset token");

        user.isVerified = true;
        await user.save();
        await VToken.deleteOne();
        if (process.env.NODE_ENV !== "test") {
            await new MailService(user).sendSuccessVerificationMail();
        }
        return true;
    }

    async requestPasswordReset(username_email: string) {
        if (!username_email) throw new CustomError("email/username is required");

        const user = await User.findOne({ $or: [{ email: username_email }, { username: username_email }] });
        if (!user) throw new CustomError("email does not exist");

        const token = await Token.findOne({ userId: user._id, type: "reset_password" });
        if (token) await token.deleteOne();

        const resetToken = crypto.randomBytes(32).toString("hex");
        const hash = await bcrypt.hash(resetToken, 10);

        await new Token({
            token: hash,
            userId: user._id,
            type: "reset_password",
            expiresAt: Date.now() + ms("15min")
        }).save();

        const link = `${URL.CLIENT_URL}/auth/reset-password/${user._id}/${resetToken}`;

        if (process.env.NODE_ENV !== "test") {
            await new MailService(user).sendPasswordResetMail(link);
        }

        return { resetToken };
    }

    async requestEmailVerification(email: string) {
        if (!email) throw new CustomError("email not provided");
        const user = await User.findOne({ email: email });
        if (!user) throw new CustomError("user does not exist");
        if (user.isVerified) throw new CustomError("email is already verified");

        const token = await Token.findOne({ userId: user._id, type: "verify_email" });
        if (token) await token.deleteOne();

        const verifyToken = crypto.randomBytes(32).toString("hex");
        const hash = await bcrypt.hash(verifyToken, 10);

        await new Token({
            token: hash,
            userId: user._id,
            type: "verify_email",
            expiresAt: Date.now() + ms("15min")
        }).save();

        const link = `${URL.CLIENT_URL}/auth/email-verification/${user._id}/${verifyToken}`;

        if (process.env.NODE_ENV !== "test") {
            await new MailService(user).sendEmailVerificationMail(link);
        }

        return { verifyToken };
    }

    async resetPassword(data: ResetPasswordInput) {
        const { userId, resetToken, password, confirmPassword } = data;

        if (!userId || !resetToken || !password || !confirmPassword) throw new CustomError("Please provided all required fields");
        const user = await User.findById(userId);

        if (!user) throw new CustomError("user not found");

        const RToken = await Token.findOne({ userId, type: "reset_password" });
        if (!RToken) throw new CustomError("invalid or expired password reset token");
        if (RToken.expiresAt < new Date(Date.now())) throw new CustomError("invalid or expired email verification token");

        const isValid = await bcrypt.compare(resetToken, RToken.token);
        if (!isValid) throw new CustomError("invalid or expired password reset token");

        if (password !== confirmPassword) throw new CustomError("Password does not match");

        const validate = await this.isPasswordValid({ password });

        if (!validate) {
            throw new CustomError("Password must contain at least one capital letter, one special character, one number, one small letter, and be at least 8 characters long");
        }
        (user as any).password = password;
        user.save();
        if (process.env.NODE_ENV !== "test") {
            await new MailService(user).sendSuccessPasswordReset();
        }
        return true;
    }

    async updatePassword(userId: string, data: UpdatePasswordInput) {
        if (!data.oldPassword || !data.newPassword || !data.confirmPassword) throw new CustomError("Please provide all required fields");

        const user = await User.findOne({ _id: userId }).select("+password");
        if (!user) throw new CustomError("user dose not exist");

        const isCorrect = await bcrypt.compare(data.oldPassword, user.password);
        if (!isCorrect) throw new CustomError("incorrect password");

        if (data.oldPassword == data.newPassword) throw new CustomError("change password to something different");

        if (data.newPassword !== data.confirmPassword) throw new CustomError("Password does not match");

        const validate = await this.isPasswordValid({
            password: data.newPassword
        });

        if (!validate) {
            throw new CustomError("Password must contain at least one capital letter, one special character, one number, one small letter, and be at least 8 characters long");
        }

        const hash = await bcrypt.hash(data.newPassword, 10);

        await User.updateOne({ _id: userId }, { $set: { password: hash } }, { new: true });

        return true;
    }
    async isPasswordValid(data: PasswordValidator) {
        const { password } = data;
        const capitalLetterRegex = /[A-Z]/;
        const specialCharRegex = /[!@#$%^&*.]/;
        const numberRegex = /[0-9]/;
        const smallLetterRegex = /[a-z]/;

        return capitalLetterRegex.test(password) && specialCharRegex.test(password) && numberRegex.test(password) && smallLetterRegex.test(password) && password.length >= 8;
    }

    async usernameValidator(data: UsernameValidator) {
        const { username } = data;
        const regex = /^(?=.*[a-z])[a-z0-9_.-]{4,15}$/i;

        return regex.test(username);
    }
}

export default new AuthService();
