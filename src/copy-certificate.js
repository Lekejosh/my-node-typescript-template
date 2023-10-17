const fs = require("fs-extra");
const path = require("path");

const srcCertificateFolder = path.join(__dirname, "certificate");
const destCertificateFolder = path.join(__dirname, "../", "dist", "certificate");

fs.copySync(srcCertificateFolder, destCertificateFolder);
