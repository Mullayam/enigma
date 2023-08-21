import { EncryptaKeyHeaders, Options } from './interface.js'
import { SecureToken } from './SecureToken.js';

export namespace Inscribe {

    export class EncryptoJWT extends SecureToken {
        constructor(protected SecretKey: string) {
            super(SecretKey)
        }

        /**
         * A method to add custom headers to the CryptoSeal object.
         *
         * @param {any} myheaders - The custom headers to be added.
         * @return {void} The updated CryptoSeal object.
         */
        customHeader(myheaders: any): this {
            this.CryptoSeal = { ...this.CryptoSeal, ...myheaders }
            return this
        }
        /**
         * Generates a signed JWT token based on the given payload and options.
         *
         * @param {any} payload - The payload to include in the token.
         * @param {Options} [options] - The options for generating the token.
         * @param {number} [options.expiresIn=0] - The expiration time for the token in seconds.
         * @return {string} - The signed JWT token.
         */
        safesign(payload: any, options: Options = { expiresIn: 0 }): string {
            return `${this.CreateEncodedHeader()}.${this.CreateEncodedPayload({ payload, expiresIn: options.expiresIn })}.${this.CreateEncodedSignature(payload)}`;
        }
        confirm(token: string):boolean {
            return this.IsValidToken(token)
        }
        decrypt(token: string):any {
            return this.ParseTokenString(token)

        }

    }
}