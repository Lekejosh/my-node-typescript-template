export const PORT = process.env.PORT;
export const MONGO_URL = process.env.MONGODB_URI || "";
export const MONGODB_URI_DEV = process.env.MONGODB_URI_DEV || "";
export const REDIS_HOST_DEV = process.env.REDIS_HOST_DEV;
export const REDIS_HOST = process.env.REDIS_HOST;
export const REDIS_PORT = process.env.REDIS_PORT;
export const BCRYPT_SALT = process.env.BCRYPT_SALT;
export const APP_NAME = "my-node-typescript-template";
export const JWT_SECRET = process.env.JWT_SECRET;

export const ROLE = {
    ADMIN: ["admin"],
    USER: ["user", "admin"]
};

export const URL = {
    CLIENT_URL: process.env.CLIENT_URL || "http://localhost:3000"
};
export const MAILER = {
    USER: process.env.MAILER_USER,
    PORT: process.env.MAILER_PORT,
    SECURE: process.env.MAILER_SECURE,
    PASSWORD: process.env.MAILER_PASSWORD,
    HOST: process.env.MAILER_HOST
};

export const CLOUDINARY = {
    APIKEY: process.env.CLOUDINARY_APIKEY,
    SECRET: process.env.CLOUDINARY_SECRET,
    NAME: process.env.CLOUDINARY_NAME
};
