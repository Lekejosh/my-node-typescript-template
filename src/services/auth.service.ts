/* eslint-disable @typescript-eslint/no-explicit-any */
import ms from "ms";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import JWT from "jsonwebtoken";

import User from "./../models/user.model";
import MailService from "./mail.service";
import CustomError from "../utils/custom-error";
import { JWT_SECRET, URL } from "../config";
import client from "../database/redis";
class AuthService {
    async register(data: RegisterInput) {
        if (!data.name || !data.password || !data.email || !data.dateOfBirth || !data.gender || !data.termsOfService) throw new CustomError("Please provide all required  fields");

        let user = await User.findOne({ email: data.email });
        if (user) throw new CustomError("email already exists");

        const validate = await this.isPasswordValid({ password: data.password });

        if (!validate) {
            throw new CustomError("Password must contain at least one capital letter, one special character, one number, one small letter, and be at least 8 characters long");
        }

        user = await new User(data).save();

        await this.requestEmailVerification(user._id.toString());

        const authTokens = await this.generateAuthTokens({
            userId: user._id,
            role: user.role
        });

        return {
            user,
            token: authTokens.accessToken,
            refreshToken: authTokens.refreshToken
        };
    }

    async login(data: LoginInput) {
        if (!data.email) throw new CustomError("email is required");
        if (!data.password) throw new CustomError("password is required");

        // Check if user exist
        const user = await User.findOne({ email: data.email }).select("+password");
        if (!user) throw new CustomError("incorrect email or password");

        // Check if user password is correct
        const isCorrect = await bcrypt.compare(data.password, user.password);
        if (!isCorrect) throw new CustomError("incorrect email or password");

        const authTokens = await this.generateAuthTokens({
            userId: user._id,
            role: user.role
        });

        user.password = "";

        await client.del(user._id.toString());
        const stringify = JSON.stringify(user);
        await client.setEx(user._id.toString(), 85000, stringify);

        return {
            user,
            token: authTokens.accessToken,
            refreshToken: authTokens.refreshToken
        };
    }

    async generateAuthTokens(data: GenerateTokenInput) {
        const { userId, role } = data;

        const accessToken = JWT.sign({ id: userId, role }, JWT_SECRET!, {
            expiresIn: "15m"
        });

        const refreshToken = crypto.randomBytes(32).toString("hex");
        const hash = await bcrypt.hash(refreshToken, 10);

        const refreshTokenJWT = JWT.sign({ userId, refreshToken }, JWT_SECRET!, {
            expiresIn: "1 day"
        });

        const tokenData = {
            userId: userId,
            token: hash,
            type: "refresh_token",
            expiresAt: Date.now() + ms("1 day")
        };

        const redisData = `refresh_token-${userId}`;

        await client.set(redisData, JSON.stringify(tokenData));

        return { accessToken, refreshToken: refreshTokenJWT };
    }

    async refreshAccessToken(data: RefreshTokenInput) {
        const { refreshToken: refreshTokenJWT } = data;

        const decoded: any = JWT.verify(refreshTokenJWT, JWT_SECRET!);
        let { refreshToken } = decoded;
        const { userId } = decoded;
        let user;

        const userString = await client.get(userId);

        if (!userString) {
            user = await User.findById(userId);
            if (!user) throw new CustomError("User not found");

            const userdata = JSON.stringify(user);
            await client.setEx(userId, 86400, userdata);
        } else {
            user = JSON.parse(userString);
        }
        const redisData = `refresh_token-${userId}`;

        const token = await client.get(redisData);

        if (!token) throw new CustomError("invalid or expired refresh token");

        const parsedToken = JSON.parse(token);

        const isValid = await bcrypt.compare(refreshToken, parsedToken.token);

        if (!isValid) {
            await client.del(redisData);
        }
        await client.del(redisData);

        const accessToken = JWT.sign({ id: user._id, role: user.role }, JWT_SECRET!, {
            expiresIn: "15m"
        });

        refreshToken = crypto.randomBytes(32).toString("hex");
        const hash = await bcrypt.hash(refreshToken, 10);

        const refreshTokenJWTNew = JWT.sign({ userId, refreshToken }, JWT_SECRET!, {
            expiresIn: "1 day"
        });

        const tokenData = {
            userId: userId,
            token: hash,
            type: "refresh_token",
            expiresAt: Date.now() + ms("1 day")
        };

        await client.set(redisData, JSON.stringify(tokenData));

        return { accessToken, refreshTokenJWTNew };
    }

    async logout(data: LogoutInput) {
        const { refreshToken: refreshTokenJWT } = data;

        const decoded: any = JWT.verify(refreshTokenJWT, JWT_SECRET!);
        const { refreshToken, userId } = decoded;
        const redisData = `refresh_token-${userId}`;
        const token = await client.get(redisData);

        if (!token) throw new CustomError("invalid or expired refresh token or user does not exist");
        const parsedToken = JSON.parse(token);

        const isValid = await bcrypt.compare(refreshToken, parsedToken.token);

        if (!isValid) {
            await client.del(redisData);
            throw new CustomError("invalid or expired refresh token");
        }
        await client.del(userId);
        await client.del(redisData);

        return true;
    }

    async verifyEmail(data: VerifyEmailInput, userId: string) {
        const { verifyToken } = data;

        const user = await User.findById(userId);
        if (!user) throw new CustomError("User with this Id not found");

        if (user.isVerified) throw new CustomError("Email is already verified");
        const emailResetData = `email_verify-${userId}`;
        const verificationInfo = await client.get(emailResetData);

        const emailVerificationToken = crypto.createHash("sha256").update(verifyToken).digest("hex");

        if (!verificationInfo || emailVerificationToken !== verificationInfo) throw new CustomError("Token Invalid or expired");
        user.isVerified = true;
        await user.save();
        await client.del(emailResetData);
        await client.del(userId as string);
        const stringify = JSON.stringify(user);
        await client.setEx(userId as string, 83000, stringify);
        await new MailService(user).sendSuccessVerificationMail();
        return true;
    }

    async requestEmailVerification(userId: string) {
        const user = await User.findById(userId);

        if (!user) throw new CustomError("user does not exist", 404);
        if (user.isVerified) throw new CustomError("email is already verified");

        const verifyToken = await this.generateToken({
            userId: user._id.toString(),
            type: "email"
        });

        const link = `${URL.CLIENT_URL}/email-verification?uid=${user._id}&verifyToken=${verifyToken}`;

        // Send Mail
        await new MailService(user).sendEmailVerificationMail(link);

        return true;
    }

    async requestPasswordReset(email: string) {
        if (!email) throw new CustomError("email is required");

        const user = await User.findOne({ email });
        if (!user) throw new CustomError("email does not exist");

        const resetToken = await this.generateToken({
            userId: user._id.toString(),
            type: "password"
        });

        const link = `${URL.CLIENT_URL}/reset-password?uid=${user._id}&resetToken=${resetToken}`;

        // Send Mail
        await new MailService(user).sendPasswordResetMail(link);

        return true;
    }

    async generateToken(data: generateToken) {
        const { userId, type } = data;
        if (type === "password") {
            const resetToken = crypto.randomBytes(20).toString("hex");

            const resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");

            const emailResetData = `reset_password-${userId}`;
            await client.setEx(emailResetData, 900, resetPasswordToken);
            return resetToken;
        } else {
            const emailToken = crypto.randomBytes(20).toString("hex");

            const emailVerificationToken = crypto.createHash("sha256").update(emailToken).digest("hex");

            const emailResetData = `email_verify-${userId}`;
            await client.setEx(emailResetData, 900, emailVerificationToken);
            return emailToken;
        }
    }

    async resetPassword(data: ResetPasswordInput) {
        const { userId, resetToken, password, confirmPassword } = data;
        const resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");

        const user = await User.findById(userId);

        if (!user) throw new CustomError("Token has expired or invalid");

        const emailResetData = `reset_password-${userId}`;
        const resetInfo = await client.get(emailResetData);

        if (!resetInfo) throw new CustomError("Token has expired or invalid");

        if (!resetInfo || resetInfo !== resetPasswordToken) throw new CustomError("Token has expired or invalid");

        if (password !== confirmPassword) throw new CustomError("Paasword does not match");

        const validate = await this.isPasswordValid({ password });

        if (!validate) {
            throw new CustomError("Password must contain at least one capital letter, one special character, one number, one small letter, and be at least 8 characters long");
        }
        user.password = password;
        user.save();
        await client.del(emailResetData);
        await new MailService(user).sendSuccessPasswordReset();
        return true;
    }

    async updatePassword(userId: string, data: UpdatePasswordInput) {
        if (!data.oldPassword) throw new CustomError("password is required");
        if (!data.newPassword) throw new CustomError("new password is required");

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
        const specialCharRegex = /[!@#$%^&*]/;
        const numberRegex = /[0-9]/;
        const smallLetterRegex = /[a-z]/;

        return capitalLetterRegex.test(password) && specialCharRegex.test(password) && numberRegex.test(password) && smallLetterRegex.test(password) && password.length >= 8;
    }
}

export default new AuthService();
