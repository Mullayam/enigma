const crypto = require("crypto");
const ALGORITHM = "aes-256-cbc";
const ENCODING = "hex";
const KEY = "enjoys_encrption_key!@#%^&*()_NJ" || process.env.ENCRYPTION_KEY;

const key = {
  encrypt: (text, IV_LENGTH = 16) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return `${iv.toString(ENCODING)}:${encrypted.toString(ENCODING)}`;
  },
  decrypt: (text) => {
    const textParts = text.split(":");
    const iv = Buffer.from(textParts.shift(), ENCODING);
    const encryptedText = Buffer.from(textParts.join(":"), ENCODING);
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  },
};

module.exports = key;
