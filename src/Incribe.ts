import { EncryptaKeyHeadersType, Options } from './interface.js'
import { SecureToken } from './SecureToken.js';

export namespace Inscribe {

    export class EncryptoJWT extends SecureToken {

        /**
         * A method to add custom headers to the CryptoSeal object.
         *
         * @param {any} myheaders - The custom headers to be added.
         * @return {void} The updated CryptoSeal object.
         */
        setHeader(myheaders: any): this {
            this.CryptoSealHeaders = { ...this.CryptoSealHeaders, ...myheaders }
            return this
        }
        getHeader(tokenString: string, name: string = ""): EncryptaKeyHeadersType | keyof EncryptaKeyHeadersType {
            if (name !== "" && name) {
                const headerData = this.getDataByParts(tokenString)
                return headerData[name as keyof typeof headerData]
            }
            return this.getDataByParts(tokenString)
        }
        /**
         * Generates a signed JWT token based on the given payload and options.
         *
         * @param {any} payload - The payload to include in the token.
         * @param {Options} [options] - The options for generating the token.
         * @param {number} [options.expiresIn=0] - The expiration time for the token in seconds.
         * @return {string} - The signed JWT token.
         */
        safesign(payload: any, privateKey: string, options: Options = { expiresIn: 0 }): string {
            return `${this.CreateEncodedHeader()}.${this.CreateEncodedPayload({ payload, expiresIn: options.expiresIn })}.${this.CreateEncodedSignature(payload, privateKey)}`;
        }
        /**
         * Confirm the validity of a token.
         *
         * @param {string} token - The token to be confirmed.
         * @return {boolean} Returns true if the token is valid, otherwise false.
         */
        confirm(token: string): boolean {
            return this.IsValidToken(token)
        }
        /**
         * Decodes a given token and returns the decrypted string or object.
         *
         * @param {string} token - The token to be decoded.
         * @return {string | Record<string, any>} - The decrypted string or object.
         */
        decode(token: string): string | Record<string, any> {
            return this.decryptStringToData(token)
        }
        /**
         * Decrypts a token using the provided secret key.
         *
         * @param {string} token - The token to be decrypted.
         * @param {string} SecretKey - The secret key used for decryption.
         * @return {any} The decrypted token.
         */
        decrypt(token: string, SecretKey: string): any {
            return this.ParseTokenString(token, SecretKey)
        }

    }
}