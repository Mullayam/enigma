
<p align="center">
  <a href="https://enjoys.in">
    <img src="https://assets-docs.b-cdn.net/assets/ENJOYSLIGHT.png" height="138">
    <h1 align="center">Enigma</h1>
  </a>
</p>

<p align="center">
  <a aria-label="PreSQL logo" href="https://en-presql.enjoys.in">
    <img src="https://assets-docs.b-cdn.net/assets/lightMAdebyEnjoys.png" height="30">
  </a>
  <a aria-label="NPM version" href="https://www.npmjs.com/package/presql">
    <img alt="1.0.0" src="https://img.shields.io/badge/NPM-1.0.0-orange?style=for-the-badge&logo=appveyor">
  </a> 
</p> 

##  [Documentation](https://docs.enjoys.in/enigma)

Visit [https://docs.enjoys.in/enigma](https://docs.enjoys.in/enigma) to view the full documentation. 
> Developer : `ENJOYS`
> Version : `1.0.0` 
# Use Cases
  
ES5 Syntax (CommonJS)
```javascript
const  enigma = require("@enjoys/enigma");`
```

ES6 Syntax
```javascript
import  enigma  from('@enjoys/enigma')
```
Create New a Instance

## ENCRYPTION OF DATA
```javascript
const LockNKey= Enigma.GuardianCipher("enjoys_encryption_key!@#%^&*()_N")
```
Pass a custom Encryption key of length 32 characters to encrypt your data and convert into a string.
This key is used to decrypt your data. 
If you do not pass any key then default key is going to be use, which is dangerous so please make sure you must pass own key.
```javascript
const NewObj  = {name:"Test",isAdmin:true}
let  EncryptMyData = LockNKey.encrypt(NewObj)
```
This will return a encrypted/hash random generated string with your data and encryption key.<BR>

`Output:3b5c361644502f946dd4e624a0408d20:8494d14ed4970f21f934b87769693357a887b267c3f90b5110884b32d36444b3`

## DECRYPTION OF DATA  
```javascript
let  DecryptData = '3b5c361644502f946dd4e624a0408d20:8494d14ed4970f21f934b87769693357a887b267c3f90b5110884b32d36444b3'
```
Also can use Destructing Method
```javascript
let {user,isAdmin} = LockNKey.decrypt(DecryptData)
console.log(name,isAdmin)
```
## Create Token  
```javascript
const enigma = new Enigma.EnigmaToken();
const SecretKey = "JwtSecretKey__!@#%^&*()_NJ";
const token = enigma.safesign({ test: "test" }, SecretKey );
//if you want to set Token Expiration time 
//enigma..safesign('your_payload', SecretKey , { expiresIn: 1500 }) 
//expiresIn requires number that means only seconds
```
## Create Token  With Own Headers
```javascript
const enigma = new Enigma.EnigmaToken();
const SecretKey = "JwtSecretKey__!@#%^&*()_NJ";
const token = enigma.setHeader({ clientId: "random" }).safesign({ test: "test" }, SecretKey ); 
```
If you decrypt the token on JWT.io(jwt.tio), the `Header` part contains following output:
```js
{
  "alg": "HS256",
  "typ": "JWT",
  "clientId": "random"
}

```
## Get Token  Headers
```javascript
const enigma = new Enigma.EnigmaToken();
const SecretKey = "JwtSecretKey__!@#%^&*()_NJ";
const Encryptedtoken ="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIm5hbWUiOiJtdWxsYXlhbSJ9.eyJ0ZXN0IjoidGVzdCIsImlzcyI6ImVuaWdtYSIsImlhdCI6MTY5MjY5MzEyNCwiZXhwaXJlc0luIjoxNjkyNjkzMTI1NTM4fQ"
const tokenHeaders = enigma.getHeader(Encryptedtoken, SecretKey ); 
console.log(alg)
```
Output Will be:
```bash
HS256
```
## Check Token is Valid Or Not
```javascript
const enigma = new Enigma.EnigmaToken();
const Encryptedtoken ="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIm5hbWUiOiJtdWxsYXlhbSJ9.eyJ0ZXN0IjoidGVzdCIsImlzcyI6ImVuaWdtYSIsImlhdCI6MTY5MjY5MzEyNCwiZXhwaXJlc0luIjoxNjkyNjkzMTI1NTM4fQ"
const isValid= enigma.confirm(Encryptedtoken); 
console.log(isValid)
```
Output Will be:
if token is valid and not expired and not malformed
```bash
true 
```
## Decrypt Token 
```javascript
const enigma = new Enigma.EnigmaToken();
const SecretKey = "JwtSecretKey__!@#%^&*()_NJ";
const Encryptedtoken ="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsIm5hbWUiOiJtdWxsYXlhbSJ9.eyJ0ZXN0IjoidGVzdCIsImlzcyI6ImVuaWdtYSIsImlhdCI6MTY5MjY5MzEyNCwiZXhwaXJlc0luIjoxNjkyNjkzMTI1NTM4fQ"
const decodedToken= decrypt.confirm(Encryptedtoken,SecretKey ); 
console.log(decodedToken)
```
Output Will be: 
```bash
{
  "test": "test",
  "iss": "enigma",
  "iat": 1692693124,
  "expiresIn": 1692693125538
}
```