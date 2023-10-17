import mongoose from "mongoose";

import { MONGODB_URI_DEV, MONGO_URL } from "../config";

const isDocker = process.env.DOCKER === "true";
const mongoURL = isDocker ? `${MONGODB_URI_DEV}` : `${MONGO_URL}`;

mongoose
    .connect(mongoURL)
    .then(() => {
        console.log(`:::>  Database connected`);
    })
    .catch((err) => {
        console.error(err);
    });
