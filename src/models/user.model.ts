import bcrypt from "bcryptjs";
import { randomUUID } from "crypto";
import mongoose from "mongoose";

export interface IUser extends mongoose.Document {
    id: string;
    first_name: string;
    last_name: string;
    email: string;
    username: string;
    isVerified: boolean;
    phone_number: number;
    password: string;
    role: "user" | "admin";
    createdAt: Date;
    updatedAt: Date;
}

const userSchema: mongoose.Schema = new mongoose.Schema(
    {
        _id: {
            type: String,
            default: randomUUID()
        },
        first_name: {
            type: String,
            required: true,
            trim: true
        },
        last_name: {
            type: String,
            required: true,
            trim: true
        },
        username: {
            type: String,
            required: true,
            trim: true,
            unique: true,
            set: function (value: string) {
                return value.toLowerCase();
            }
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            validate: {
                validator: function (value: string) {
                    return /^[\w\-]+(\.[\w\-]+)*@([\w-]+\.)+[\w-]{2,}$/gm.test(value);
                },
                message: "Invalid email format"
            }
        },
        phone_number: {
            type: Number
        },
        isVerified: {
            type: Boolean,
            default: false
        },
        password: {
            type: String,
            required: true,
            select: false
        },
        role: {
            type: String,
            default: "user",
            enum: ["user", "admin"]
        }
    },
    {
        timestamps: true,
        toJSON: {
            transform: function (doc, ret) {
                ret.id = ret._id;
                delete ret._id;
                delete ret.password;
                delete ret.__v;
                delete ret.identification;
            }
        }
    }
);

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    const hash = await bcrypt.hash(this.password, 10);
    this.password = hash;

    next();
});

export default mongoose.model<IUser>("user", userSchema);
