import multer from "multer";
import path from "path";
// import CustomError from "./custom-error";

export default multer({
    storage: multer.diskStorage({}),
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        if (ext !== ".jpg" && ext !== ".jpeg" && ext !== ".png") {
            cb(null, false);
        } else {
            cb(null, true);
        }
    }
});
