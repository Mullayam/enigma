"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const zcrypto = require("crypto");
const ALGORITHM = "aes-256-cbc";
const ENCODING = "hex";
class Zilch {
    constructor() {
        this.ENCRYPTION_KEY = "enjoys_encrption_key!@#%^&*()_NJ" || process.env.ENCRYPTION_KEY;
        this.IV_LENGTH = 16;
    }
    static ENCRYPTION_KEY(CUSTOM_SECRET_KEY) {
        return `${CUSTOM_SECRET_KEY} || process.env.ENCRYPTION_KEY`;
    }
    config(USER_ENCRYPTION_KEY) {
        if (USER_ENCRYPTION_KEY) {
            this.ENCRYPTION_KEY = USER_ENCRYPTION_KEY;
            return `${this.ENCRYPTION_KEY}`;
        }
        return `${this.ENCRYPTION_KEY}`;
    }
    encrypt(data) {
        const iv = zcrypto.randomBytes(this.IV_LENGTH);
        const cipher = zcrypto.createCipheriv(ALGORITHM, Buffer.from(this.ENCRYPTION_KEY), iv);
        let encrypted = cipher.update(data);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return `${iv.toString(ENCODING)}:${encrypted.toString(ENCODING)}`;
    }
    decrypt(text) {
        const textParts = text.split(":");
        const iv = Buffer.from(textParts.shift(), ENCODING);
        const encryptedText = Buffer.from(textParts.join(":"), ENCODING);
        const decipher = zcrypto.createDecipheriv(ALGORITHM, Buffer.from(this.ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    }
}
module.exports = new Zilch();
//# sourceMappingURL=index.js.map