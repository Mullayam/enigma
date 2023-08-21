import * as crypto from 'crypto'
import { CreateEncodedPayloadType, EncryptaKeyHeaders } from "./interface.js";

export class SecureToken {
    constructor(protected SecretKey: string) {
        this.SecretKey = SecretKey
    }
    protected CryptoSeal: EncryptaKeyHeaders = { alg: "HS256", typ: "JWT" }
    /**
     * Encodes the given data in base64 format.
     *
     * @param {any} data - The data to be encoded.
     * @return {string} The encoded data in base64 format.
     */
    protected EncodeDataInBase64(data: any): string {
        return Buffer.from(JSON.stringify(data)).toString('base64');
    }
    /**
     * Replaces occurrences of '=' with '', '+' with '-', and '/' with '_' in the given string.
     *
     * @param {string} string - The string to be filtered.
     * @return {string} The filtered string.
     */
    protected FilterMyString(string: string): string {
        return string.replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
    }
    /**
     * Creates an encoded header.
     *
     * @return {string} The encoded header.
     */
    protected CreateEncodedHeader(): string {
        return this.FilterMyString(this.EncodeDataInBase64(this.CryptoSeal))
    }
    /**
     * Creates an encoded payload using the provided data.
     *
     * @param {Object} data - The data object containing the payload and optional expiresIn value.
     * @param {any} data.payload - The payload to be encoded.
     * @param {number} [data.expiresIn] - The expiration time in milliseconds. Optional, defaults to undefined.
     * @returns {string} - The encoded payload.
     */
    protected CreateEncodedPayload(data: { payload: any, expiresIn?: number }): string {
        const VaultedToken = { ...data.payload, iat: new Date().getTime() } as CreateEncodedPayloadType

        if (data.expiresIn !== 0) {
            VaultedToken.expiresIn = new Date().getTime() + Number(data.expiresIn)
        }
        return this.FilterMyString(this.EncodeDataInBase64(VaultedToken))
    }
    /**
     * Generates an encoded signature for the given payload.
     *
     * @param {any} payload - The payload to create the signature for.
     * @return {string} The encoded signature.
     */
    protected CreateEncodedSignature(payload: any): string {
        const Signature = crypto
            .createHmac("sha256", this.SecretKey)
            .update(`${this.CreateEncodedHeader()}.${this.CreateEncodedPayload(payload)}`)
            .digest("base64")

        return this.FilterMyString(Signature)
    }
    /**
     * Validates the format of a JWT token.
     *
     * @param {string} token - The JWT token to validate.
     * @throws {Error} If the token is not in the correct format.
     */
    protected IsValidToken(token: string): boolean | any {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid Token');
            }
            if (this.CheckJSON(parts[1])) {
                const payload = JSON.parse(this.DecodeBase64String(parts[1]));
                if (payload?.expiresIn < new Date().getTime()) {
                    throw new Error('Token is expired');
                }
                return true
            }
            throw new Error('Token is Malformed')

        } catch (error: any) {
            return `${error.message}`
        }
    }
    /**
     * Decodes a base64 encoded string.
     *
     * @param {string} str - The base64 encoded string to decode.
     * @return {string} - The decoded string.
     */
    private DecodeBase64String(str: string): string {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        while (str.length % 4) {
            str += '=';
        }
        return atob(str);
    }
    private CheckJSON(part: string): boolean {
        try {
            JSON.parse(this.DecodeBase64String(part))
            return true;

        } catch (error) {
            return false
        }
    }
    private VerifySignature(data: { payload: any, header: string }, signature: string) {
        const calculatedSignature = crypto
            .createHmac('sha256', this.SecretKey)
            .update(`${data.header}.${data.payload}`)
            .digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        return calculatedSignature === signature;

    }
    protected ParseTokenString(TokenStr: string): any {
        try {
            this.IsValidToken(TokenStr)
            const parts = TokenStr.split('.');
            const payload = JSON.parse(this.DecodeBase64String(parts[1]));
            const header = JSON.parse(this.DecodeBase64String(parts[0]));
            const signature = parts[2];
            if (!this.VerifySignature({ payload: JSON.stringify(payload), header: JSON.stringify(header) }, signature)) {
                throw new Error('Invalid Signature')
            }
            return payload
        } catch (error: any) {
            return `${error.message}`
        }
    }

}