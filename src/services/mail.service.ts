import nodemailer, { TransportOptions } from "nodemailer";

import { MAILER, APP_NAME } from "./../config";
import CustomError from "../utils/custom-error";

import type { IUser } from "./../models/user.model";

class MailService {
    user: IUser;

    constructor(user: IUser) {
        this.user = user;
    }

    async send(subject: string, content: string, recipient: string) {
        content = content || " ";

        if (!recipient || recipient.length < 1) throw new CustomError("Recipient is required");
        if (!subject) throw new CustomError("Subject is required");

        // Define nodemailer transporter
        const transporter = nodemailer.createTransport({
            host: MAILER.HOST,
            port: MAILER.PORT,
            secure: true,
            requireTLS: true,
            auth: {
                user: MAILER.USER,
                pass: MAILER.PASSWORD
            }
        } as TransportOptions);

        const result = await transporter.sendMail({
            from: `${APP_NAME} <${MAILER.USER}>`,
            to: Array.isArray(recipient) ? recipient.join() : recipient,
            subject,
            text: content
        });

        if (!result) throw new CustomError("Unable to send mail");

        return result;
    }

    async sendEmailVerificationMail(link: string) {
        const subject = "Email Verification";
        const content = `Hey ${this.user.name}, Please click on the link to verify your email ${link}`;
        const recipient = this.user.email;

        return await this.send(subject, content, recipient);
    }

    async sendSuccessVerificationMail() {
        const subject = "Verified Successfully";
        const content = `Your email has been verified successfully`;
        const recipient = this.user.email;

        return await this.send(subject, content, recipient);
    }

    async sendPasswordResetMail(link: string) {
        const subject = "Reset password";
        const content = `Hey ${this.user.name}, Please click on the link to reset your password ${link}`;
        const recipient = this.user.email;

        return await this.send(subject, content, recipient);
    }

    async sendSuccessPasswordReset() {
        const subject = "Password Changed";
        const content = `Your password has been changed successfully`;
        const recipient = this.user.email;

        return await this.send(subject, content, recipient);
    }
}

export default MailService;
