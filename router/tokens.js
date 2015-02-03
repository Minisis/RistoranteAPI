'use strict';

var express = require('express'),
		assert = require('assert'),
		jwt = require('jwt-simple'),
		async = require('async'),
		_ = require('underscore'),
		router = express.Router(),
		UserModel = require('./../model/user'),
		wrappedResponse = require('./../util').wrappedResponse,
		crypto = require('./../util').crypto;

//create new tokens
router.post('/' , function(req , res , next) {
	var body = req.body;
	//validate body information
	try {
		assert.strictEqual(typeof body.email , 'string');
		assert.ok(body.email);
		assert.ok(/^(?:[a-z0-9A-Z_.-]+)@(?:[A-Z0-9a-z]+).(?:[a-zA-Z]+)/.test(body.email));
		assert.ok(body.password);
	}
	catch(e) {
		//return 400 here
		return wrappedResponse({ res : res,
									  				 code : 400,
						  							 message : 'invalid bodyname or password',
						  							 data : 'InvalidCredentials' });
	}
	//User credentials are ok.
	//let's check if body password is okay
	UserModel.findOne({ email : body.email } , function(err , user) {
		var strategy,
				tokens,
				token,
				isNewTkn;
		if (err) return next(err);
		if (user && user.strategies) {
			tokens = user.tokens;
			strategy = _.find(user.strategies , function(str) {
				return str.type === body.type;
			}); 
			if ( strategy.password.hash === crypto.createHash(body.password , strategy.password.salt , 'sha512') ) {
				//body provided correct credentials, let's create a valid token
				async.doWhilst(function(callback) {	
					crypto.createSalt(32 , function(err , salt) {
						if (err) return callback(err);
						var payload = { email : body.email ,
												 		type : body.type };
						token = { hash : jwt.encode(payload , salt , 'HS512') };
						//token, created, if token exits already, we cannot push
						isNewTkn = _.find(tokens , function(tkn) {
							return tkn.hash === token.hash;
						});
						callback();
					});
				},
				function() {
					return isNewTkn;
				},
				function(err) {
					if (err) return next(err);
					tokens.push(token);
					user.save(function(err , doc) {
						if (err) return next(err);
						var body = {
							id : doc._id,
							token : doc.tokens[doc.tokens.length - 1]
						};
						//user saved, respond with token...
						return wrappedResponse({ res : res,
														  			 code : 201,
							  										 data : body,
							  										 message : '' });
					});
				});
			}
			else {
				return wrappedResponse({ res : res,
																 code : 400,
																 message : 'incorrect bodyname or password',
																 data : 'IncorrectCredentials' });
			}
		}
		else {
			//incorrect bodyname or password
			return wrappedResponse({ res : res,
															 code : 400,
															 message : 'incorrect bodyname or password',
															 data : 'IncorrectCredentials' });
		}
	});
});

module.exports = router;

