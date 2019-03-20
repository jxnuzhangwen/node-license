var addon = require('../build/Release/licence');
var fs = require('fs');




console.log("机器码：" + addon.MachineCode());
console.log("注册码：" + addon.SerialNumber());

var licence = "8ef425ff7de4c381";

require.extensions[".jse"] = function (module, filename) {
  var content = addon.RequireJSE(licence, fs.readFileSync(filename));
 	return module._compile(content, filename);
};

var ras = require("./rsa.jse");
console.log(ras.test());

