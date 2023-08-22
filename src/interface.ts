export interface EncryptaKeyHeadersType {
    [key: string]: string
    alg: string
    typ: string
}
export interface CreateEncodedPayloadType {
    [key: string]: any
    iat: number
    iss?: string
    expiresIn?: number
}
export interface Options {
    expiresIn?: number
}
export interface CypherLockType {
    encrypt(data: any): string;
    decrypt(text: any): any;
}
export type EncodingsType = "base64" | "hex" | "utf8" | "ascii" | "binary" | "utf-8"