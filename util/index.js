'use strict';

var crypto = require('crypto'),
		util = {};

util.wrappedResponse = function (spec) {
	//getting parameters...
	var res = spec.res;
	var code = spec.code;
	var message = spec.message;
	var data = spec.data;
	//creating wrapped response..
	var wr = {
		code : code,
		data : data
	};
	if (code >= 500 && code <= 599) {
		wr.status = 'fail';
		wr.message = message;
	}
	else if (code >= 400 && code <= 499) {
		wr.status = 'error';
		wr.message = message;
	}
	else {
		wr.status = 'success';
		wr.message = '';
	}
	res.status(code).json(wr);
};

util.crypto = {
	createSalt : function(bytes , cb) {
		crypto.randomBytes(bytes , function(err , buf) {
			if (err) return cb(err , null);
			cb(null , buf.toString());
		});
	},
	createHash : function(pass , salt , hash) {
		var hash = crypto.createHash(hash);
		hash.update(pass);
		hash.update(salt);
		return hash.digest('base64');
	}
};

util.cors = function(spec) {
	var origin = spec.origin,
			methods = spec.methods,
			headers = spec.headers;
	return function(req , res , next) {
		res.header('Access-Control-Allow-Origin' , origin);
		res.header('Access-Control-Allow-Methods' , methods);
		res.header('Access-Control-Allow-Headers' , headers);
		if (req.method === 'OPTIONS') {
			res.send();	
		}
		else {
			next();
		}
	};
};

module.exports = util;
