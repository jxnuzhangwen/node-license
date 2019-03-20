// load core crypto to get OpenSSL initialized
var crypto = require('crypto');
var rsa2 = require('./rsa2.jse');

exports.test = function(){
	return rsa2.test();
}
