import express from "express";
import "express-async-errors";
import cookieParser from "cookie-parser";
import session from "express-session";

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

import preRouteMiddleware from "./middlewares/pre-route.middleware";
preRouteMiddleware(app);
import routes from "./routes";
app.use(routes);
import errorMiddleware from "./middlewares/error.middleware";
errorMiddleware(app);
