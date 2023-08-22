import { SentinelCipher } from './src/Cipher.js';
import { Inscribe } from './src/Incribe.js'

export namespace Enigma {
  export class EnigmaToken extends Inscribe.EncryptoJWT {}
  export class GuardianCipher extends SentinelCipher.CypherLock {
    constructor(ENCRYPTION_KEY:string) {
      super(ENCRYPTION_KEY)
    }
  }
}
