import { CypherLockType } from "./interface.js";
import * as zcrypto from 'crypto'

export namespace SentinelCipher {
  export class CypherLock implements CypherLockType {
    private ALGORITHM: string = "aes-256-cbc";
    private IV_LENGTH = 16;
    constructor(protected ENCRYPTION_KEY: string = "encrption_key!@@@###**%#%^&*()_NJ") {
      this.ENCRYPTION_KEY = ENCRYPTION_KEY
    }    
   
    /**
     * Encrypts the given data using the AES encryption algorithm.
     *
     * @param {any} data - The data to be encrypted. It can be of any type.
     * @return {string} The encrypted data represented as a string.
     */
    encrypt(data: any): string {
      if (typeof data === "object") {
        data = JSON.stringify(data);
      }
      const iv = zcrypto.randomBytes(this.IV_LENGTH);
      const cipher = zcrypto.createCipheriv(
        this.ALGORITHM,
        Buffer.from(this.ENCRYPTION_KEY),
        iv
      );
      let encrypted = cipher.update(data);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
    }
    /**
     * Decrypts the given text using the specified algorithm and encryption key.
     *
     * @param {any} text - The text to be decrypted.
     * @return {any} - The decrypted text.
     */
    decrypt(text: any): any {
      const textParts = text.split(":");
      const iv = Buffer.from(textParts.shift(), "hex");
      const encryptedText = Buffer.from(textParts.join(":"), "hex");
      const decipher = zcrypto.createDecipheriv(
        this.ALGORITHM,
        Buffer.from(this.ENCRYPTION_KEY),
        iv
      );
      let decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher.final()]);

      return decrypted.toString();
    }
  }


}