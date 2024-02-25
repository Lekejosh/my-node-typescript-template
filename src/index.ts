import http from "http";
import cloudinary from "cloudinary";
import "dotenv/config";
import { app } from "./app";
import { CLOUDINARY, PORT } from "./config";
const httpServer = http.createServer(app);
import "./database/index";
const start = async () => {
    try {
        cloudinary.v2.config({
            cloud_name: CLOUDINARY.NAME,
            api_key: CLOUDINARY.APIKEY,
            api_secret: CLOUDINARY.SECRET
        });
    } catch (error) {
        console.error(error);
    }
    httpServer.listen(PORT, async () => {
        console.log(`:::> 🚀 Server ready at http://localhost:${PORT}`);
    });
};

start();
