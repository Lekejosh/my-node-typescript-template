import mongoose from "mongoose";

export interface IToken extends mongoose.Document {
    userId: string;
    token: string;
    type: "reset_password" | "verify_email" | "refresh_token";
    expiresAt: Date;
}

const tokenSchema: mongoose.Schema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        ref: "user"
    },
    token: {
        type: String,
        required: true
    },
    type: {
        type: String,
        required: true,
        enum: ["reset_password", "verify_email", "refresh_token"]
    },
    expiresAt: {
        type: Date,
        required: true
    }
});

export default mongoose.model<IToken>("token", tokenSchema);
