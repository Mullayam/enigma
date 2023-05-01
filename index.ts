const zcrypto = require("crypto");
const ALGORITHM = "aes-256-cbc";
const ENCODING = "hex";
interface ZilchType {
  encrypt(data: any): string;
  decrypt(text: any): any;
}
class Zilch implements ZilchType {
  private ENCRYPTION_KEY: string =
    "enjoys_encrption_key!@#%^&*()_NJ" || process.env.ENCRYPTION_KEY;
  private IV_LENGTH = 16;
  constructor() {}

  public static ENCRYPTION_KEY(CUSTOM_SECRET_KEY: string): string {
    return `${CUSTOM_SECRET_KEY} || process.env.ENCRYPTION_KEY`;
  }
  public config(USER_ENCRYPTION_KEY: string): string {
    if (USER_ENCRYPTION_KEY) {
      this.ENCRYPTION_KEY = USER_ENCRYPTION_KEY;
      return `${this.ENCRYPTION_KEY}`;
    }
    return `${this.ENCRYPTION_KEY}`;
  }
  encrypt(data: any): string {
    if (typeof data === "object") {
      data = JSON.stringify(data);
    }
    const iv = zcrypto.randomBytes(this.IV_LENGTH);
    const cipher = zcrypto.createCipheriv(
      ALGORITHM,
      Buffer.from(this.ENCRYPTION_KEY),
      iv
    );
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return `${iv.toString(ENCODING)}:${encrypted.toString(ENCODING)}`;
  }
  decrypt(text: any): any {
    const textParts = text.split(":");
    const iv = Buffer.from(textParts.shift(), ENCODING);
    const encryptedText = Buffer.from(textParts.join(":"), ENCODING);
    const decipher = zcrypto.createDecipheriv(
      ALGORITHM,
      Buffer.from(this.ENCRYPTION_KEY),
      iv
    );
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString();
  }
}
module.exports = new Zilch();
