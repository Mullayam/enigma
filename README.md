# zilch-npm-package-enjoys
Developer : `Mulayam`
<br>
Before implementing Please Provide A Secret Key in environment variable (.env File with name) if not this env variable not found then package will use default encryption key.
IN .ENV FILE

``` javascript
ENCRYPTION_KEY = "YOUR SECRET KEY"
```
# ENCRYPTION OF DATA
 
```javascript 
const Zilch = require("zilch2");`  ES5 Syntax (CommonJS)
```
ES6 Syntax 
``` javascript  
import Zilch from('zilch2')
```  
``` javascript 
const  NewObj = 'pass your data here' // { user:"demo",password:"12345678" } 
```
``` javascript  
let EncryptedData  = Zilch.encrypt(NewObj)
```
This will return a encrypted/hash random generated string with your data and encryption key.<BR>
`Output : 074e48c8e3c0bc19f9e22dd7570037392e5d0bf80cf9dd51bb7808872a511b3`
 
# DECRYPTION OF DATA

``` javascript 
let DecryptData  = '074e48c8e3c0bc19f9e22dd7570037392e5d0bf80cf9dd51bb7808872a511b3'
```
Also can use Destructing Method 
```javascript 
let {user,password} = Zilch.decrypt(DecryptData)
console.log(user,password)
```

