import * as crypto from 'crypto'
import { CreateEncodedPayloadType, EncryptaKeyHeadersType } from "./interface.js";

export class SecureToken {
    protected SecretKey: string = ""

    protected EncryptionKey(SecretKey: string) {
        this.SecretKey = SecretKey
    }
    protected CryptoSealHeaders: EncryptaKeyHeadersType = { alg: "HS256", typ: "JWT" }
    /**
     * Encodes the given data in base64 format.
     *
     * @param {any} data - The data to be encoded.
     * @return {string} The encoded data in base64 format.
     */
    protected EncodeDataInBase64(data: any): string {
        return Buffer.from(JSON.stringify(data)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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
        return this.EncodeDataInBase64(this.CryptoSealHeaders).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
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
        const VaultedToken = { ...data.payload, iss: "enigma", iat: Math.floor(Date.now() / 1000) } as CreateEncodedPayloadType
        if (data.expiresIn === 0) {
            console.log("2")
            return this.EncodeDataInBase64(VaultedToken)
        }
        VaultedToken.expiresIn = new Date().getTime() + data.expiresIn!
        return this.EncodeDataInBase64(VaultedToken)

    }
    /**
     * Generates an encoded signature for the given payload.
     *
     * @param {any} payload - The payload to create the signature for.
     * @return {string} The encoded signature.
     */
    protected CreateEncodedSignature(payload: any, privateKey: string): string {
        try {
            if (!privateKey) {
                throw new Error('No Private Key')
            }
            if (privateKey === "") {
                throw new Error('Private Key cannot be a Empty String')
            }
            const EnCodedHeaderString = this.CreateEncodedHeader()
            const EnCodedPayloadString = this.CreateEncodedPayload(payload)
            const CipherToken = `${EnCodedHeaderString}.${EnCodedPayloadString}`
            const Signature = crypto.createHmac('sha256', privateKey)
            const EncryptedToken = Signature.update(CipherToken).digest("base64").replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
            return EncryptedToken
        } catch (error: any) {
            return error.message
        }
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
    /**
     * Creates a new signature based on the provided data and secret key.
     *
     * @param {Object} data - The payload and header for the signature.
     * @param {string} SecretKey - The secret key used for encryption.
     * @return {string} The calculated signature.
     */
    private CreateNewSignature(data: { payload: any, header: string }, SecretKey: string): string {
        const CipherToken = `${data.header}.${data.payload}`
        const calculatedSignature = crypto
            .createHmac('sha256', SecretKey)
            .update(CipherToken)
            .digest('base64')
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
        return calculatedSignature;

    }
    protected ParseTokenString(TokenStr: string, SecretKey: string): any {
        try {
            if (!SecretKey) {
                throw new Error('Verify Token requires Secret Key')
            }
            this.IsValidToken(TokenStr)
            const parts = TokenStr.split('.');
            const header = parts[0];
            const payload = parts[1];
            const signature = this.CreateNewSignature({ header, payload }, SecretKey)
            return this.VerifySignature(header, payload, signature, SecretKey)
        } catch (error: any) {
            return `${error.message}`
        }
    }
    protected getDataByParts(TokenStr: string): EncryptaKeyHeadersType {
        const header = TokenStr.split('.')[0];
        return JSON.parse(this.base64UrlDecode(header));
    }
    /**
     * Decodes a base64 URL string.
     *
     * @param {string} input - The base64 URL string to decode.
     * @return {string} The decoded string in UTF-8 format.
     */
    protected base64UrlDecode(input: string): string {
        const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
        const buffer = Buffer.from(base64, 'base64');
        return buffer.toString('utf-8');
    }
    protected decryptStringToData(TokenStr: string) {
        this.IsValidToken(TokenStr)
        const payload = TokenStr.split('.')[1]
        if (this.CheckJSON(payload)) {
            return JSON.parse(this.DecodeBase64String(payload))
        } else {
            return { error: "Token is Malformed" }
        }

    }
    /**
     * Verify the signature of a JWT token.
     *
     * @param {string} jwtToken - The JWT token to verify.
     * @param {string} secretKey - The secret key used to sign the JWT token.
     * @return {CreateEncodedPayloadType | string} - The decoded payload of the JWT token if the signature is valid, 
     *                           otherwise returns "Invalid Signature".
     */
    protected VerifySignature(headerB64: string, payloadB64: string, signature: string, secretKey: string): CreateEncodedPayloadType | string {
        const hmac = crypto.createHmac('sha256', secretKey);
        hmac.update(`${headerB64}.${payloadB64}`);
        const calculatedSignature = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        if (calculatedSignature === signature) {
            return JSON.parse(this.DecodeBase64String(payloadB64));
        }
        return "Invalid Signature";
    }
}