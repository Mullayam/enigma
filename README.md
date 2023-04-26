# encrypt-decrypt-npm-package-enjoys
Developer : `Mulayam`
<br>
Before implementing Please Provide A Secret Key in environment variable (.env File with name) if not this env variable not found then package will use default encryption key.
<BR>
IN .ENV FILE
 <BR>
`ENCRYPTION_KEY = "YOUR SECRET KEY"` or also you can do this 
<BR> 
#Documentation
<BR>

#ENCRYPTION OF DATA
 
`const Zilch = require("zilich");`  ES5 Syntax (CommonJS)
<BR>
OR
<BR>
`import Zilch from('zilich')`  ES6 Syntax 
<BR>
``` javascript 
let NewObj= 'pass your data here' // { user:"demo",password:"12345678"} 
```
#
<BR>
`let EncryptedData  = Zilich.encrypt(NewObj)`
<BR>
This will return a encrypted/hash random generated string with your data and encryption key.<BR>
`Output : 074e48c8e3c0bc19f9e22dd7570037392e5d0bf80cf9dd51bb7808872a511b3`
<BR> 
 
# DECRYPTION OF DATA

`let DecryptData  = '074e48c8e3c0bc19f9e22dd7570037392e5d0bf80cf9dd51bb7808872a511b3'`
<BR>
Also can use Destructing Method `let {user,password} = Zilch.decrypt(DecryptData)`

