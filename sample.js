// test.js
var crypto = require('crypto');

var byteSize = 16, password = "test", defaultIterations = 10000, defaultKeyLength = 64;
var _salt = crypto.randomBytes(byteSize).toString('hex');
//var _salt = 'b28ee6f212c6e9cc9fe81484e5a815f0';
var salt = new Buffer(_salt, 'hex');
console.log('salt:', _salt);

var start = +new Date();
var res1 = crypto.pbkdf2Sync(password, salt, defaultIterations, defaultKeyLength);
console.log(`${+new Date() - start}ms`);
console.log('hash:', res1.toString('hex'));

var fastpbkdf2 = require('./build/Release/fastpbkdf2');
console.log(fastpbkdf2);

var start = +new Date();
var res2 = fastpbkdf2.sha1(password, salt, defaultIterations, defaultKeyLength);
console.log(`${+new Date() - start}ms`);
console.log('hash:', res2.toString('hex'));

console.assert(res1.toString('hex') == res2.toString('hex'));

