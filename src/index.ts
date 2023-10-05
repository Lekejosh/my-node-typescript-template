import express from "express";
import https from "https";
import http from "http";
import fs from "fs";
import path from "path";
import "express-async-errors";
import cookieParser from "cookie-parser";
import session from "express-session";
import cloudinary from "cloudinary";
import "./utils/imageWorker";
const app = express();
app.use(
  session({
    secret: "secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 1000 + 60 * 60 * 24 * 7,
    },
  })
);

app.use(cookieParser());

const certificateFolder = "certificate";

const privateKey = fs.readFileSync(
  path.join(__dirname, certificateFolder, "private.key"),
  "utf8"
);
const certificate = fs.readFileSync(
  path.join(__dirname, certificateFolder, "certificate.crt"),
  "utf8"
);
const credentials = { key: privateKey, cert: certificate };

const httpsServer = https.createServer(credentials, app);
const httpServer = http.createServer(app);

import preRouteMiddleware from "./middlewares/pre-route.middleware";
preRouteMiddleware(app);

import routes from "./routes";
app.use(routes);

import errorMiddleware from "./middlewares/error.middleware";
errorMiddleware(app);

import { PORT, CLOUDINARY } from "./config";

import "./database/index";
// import"./database/redis";

cloudinary.v2.config({
  cloud_name: CLOUDINARY.NAME,
  api_key: CLOUDINARY.APIKEY,
  api_secret: CLOUDINARY.SECRET,
});
// httpsServer.listen(PORT, async () => {
//   console.log(`:::> 🚀 Server ready at https://localhost:${PORT}`);
// });

 httpServer.listen(PORT, () => {
   console.log(
     `HTTP Server is working on http://localhost:${PORT}`
   );
 });

app.on("error", (error) => {
  console.error(`<::: An error occurred on the server: \n ${error}`);
});
