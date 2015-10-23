##fastpbkdf2 [![Build Status](https://travis-ci.org/S-YOU/node-fastpbkdf2.svg?branch=master)](https://travis-ci.org/S-YOU/node-fastpbkdf2)

Nodejs binding of https://github.com/ctz/fastpbkdf2 - CC0 License

### Install
```bash
npm install fastpbkdf2 --save
```

### Usage - similar to crypto.pbkdf2Sync

```javascript
var fastpbkdf2 = require('fastpbkdf2');

var crypto = require('crypto');
var password = "password", salt = new Buffer("salt"), iterations = 10000, keylen = 64;
var hash1 = crypto.pbkdf2Sync(password, salt, iterations, keylen);

var hash2 = fastpbkdf2.sha1(password, salt, iterations, keylen);
```

### Interface
```javascript
fastpbkdf2.sha1(password, salt, iterations, keylen);
fastpbkdf2.sha256(password, salt, iterations, keylen);
fastpbkdf2.sha512(password, salt, iterations, keylen);
```

###Build
- `sudo npm install -g node-gyp` if you don't have node-gyp installed.
- `npm install fastpbkdf2` will automatically build using node-gyp or clone this repo and use `node-gyp rebuild`.
- Build tested with nodejs 4.2.1 on OSX and Ubuntu/Debian
- `node sample` or `node test` to run tests

### License
MIT
