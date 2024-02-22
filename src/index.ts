import express from "express";
import http from "http";
import "express-async-errors";
import cookieParser from "cookie-parser";
import session from "express-session";
import cloudinary from "cloudinary";

export const app = express();
app.use(
    session({
        secret: "348d1911e5741ff7d5a20bb384d1adb2c0fb255ecf4263ba25435f17d47e4e18",
        resave: false,
        saveUninitialized: true,
        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 1000 + 60 * 60 * 24 * 7
        }
    })
);

app.use(cookieParser());

/*
 *
 *
 * This is for HTTPS server
 *
 */


const httpServer = http.createServer(app);

import preRouteMiddleware from "./middlewares/pre-route.middleware";
preRouteMiddleware(app);

import routes from "./routes";
app.use(routes);

import errorMiddleware from "./middlewares/error.middleware";
errorMiddleware(app);

import { PORT, CLOUDINARY } from "./config";

import "./database/index";
import "./workers/imageWorker";

cloudinary.v2.config({
    cloud_name: CLOUDINARY.NAME,
    api_key: CLOUDINARY.APIKEY,
    api_secret: CLOUDINARY.SECRET,
    secure: true
});


httpServer.listen(PORT, () => {
    console.log(`HTTP Server is working on http://localhost:${PORT}`);
});

app.on("error", (error) => {
    console.error(`<::: An error occurred on the server: \n ${error}`);
});
