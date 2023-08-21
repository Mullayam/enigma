export interface EncryptaKeyHeaders {
    [key: string]: string
    alg: string
    typ: string
}
export interface CreateEncodedPayloadType{
    payload: any
    iat:number
    expiresIn?:number
}
export interface Options{
    expiresIn?:number
}
export interface CypherLockType {
    encrypt(data: any): string;
    decrypt(text: any): any;
  }