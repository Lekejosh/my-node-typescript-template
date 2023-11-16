// import express from "express";
// import https from "https";
// import http from "http";
// import fs from "fs";
// import path from "path";
// import "express-async-errors";
// import cookieParser from "cookie-parser";
// import session from "express-session";
// import preRouteMiddleware from "../middlewares/pre-route.middleware";
// import errorMiddleware from "../middlewares/error.middleware";
// import routes from "../routes";
// function createServer() {
//     const app = express();
//     app.use(
//         session({
//             secret: "348d1911e5741ff7d5a20bb384d1adb2c0fb255ecf4263ba25435f17d47e4e18",
//             resave: false,
//             saveUninitialized: true,
//             cookie: {
//                 httpOnly: true,
//                 secure: true,
//                 sameSite: "none",
//                 maxAge: 1000 + 60 * 60 * 24 * 7
//             }
//         })
//     );

//     app.use(cookieParser());

//     preRouteMiddleware(app);

//     app.use(routes);

//     errorMiddleware(app);

//     app.on("error", (error) => {
//         console.error(`<::: An error occurred on the server: \n ${error}`);
//     });

//     return app;
// }

// export default createServer;
