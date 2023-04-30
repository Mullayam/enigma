declare const zcrypto: any;
declare const ALGORITHM = "aes-256-cbc";
declare const ENCODING = "hex";
interface ZilchType {
    encrypt(data: any): string;
    decrypt(text: any): any;
}
declare class Zilch implements ZilchType {
    private ENCRYPTION_KEY;
    private IV_LENGTH;
    constructor();
    static ENCRYPTION_KEY(CUSTOM_SECRET_KEY: string): string;
    config(USER_ENCRYPTION_KEY: string): string;
    encrypt(data: any): string;
    decrypt(text: any): any;
}
//# sourceMappingURL=index.d.ts.map