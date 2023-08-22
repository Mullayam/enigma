import { CypherLockType, EncodingsType } from "./interface.js";
import * as zcrypto from 'crypto'

export namespace SentinelCipher {
  export class CypherLock implements CypherLockType {
    private ALGORITHM: string = "aes-256-cbc";
    private ENCODING: EncodingsType = "hex";
    private IV_LENGTH = 16;
    constructor(protected ENCRYPTION_KEY: string = "enjoys_encrption_key!@#%^&*()_N") {
      if (this.ENCRYPTION_KEY.length !== 32) {
        throw new Error("Encryption key must be 32 characters long, got " + this.ENCRYPTION_KEY.length);
      }
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
      return `${iv.toString(this.ENCODING)}:${encrypted.toString(this.ENCODING)}`;
    }
    /**
     * Decrypts the given text using the specified algorithm and encryption key.
     *
     * @param {string} text - The string to be decrypted.
     * @return {string | object |any} - The decrypted text.
     */
    decrypt(text: string): string | object | any {
      const textParts: any[] = text.split(":");
      const iv = Buffer.from(textParts.shift(), this.ENCODING);
      const encryptedText = Buffer.from(textParts.join(":"), this.ENCODING);
      const decipher = zcrypto.createDecipheriv(
        this.ALGORITHM,
        Buffer.from(this.ENCRYPTION_KEY),
        iv
      );
      let decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      if (decrypted.toString().startsWith("[") && decrypted.toString().endsWith("]") || decrypted.toString().startsWith("{") && decrypted.toString().endsWith("}")) {
        return JSON.parse(decrypted.toString())
      }
      return decrypted.toString();
    }
  }


}