'use strict';
var config = {};

config.development = {
	database : {
		conStr : 'mongodb://localhost:27017/playing'
	},
	server : {
		ip : '127.0.0.1',
		port : 3000,
		name : 'http://localhost:3000'
	},
	client : {
		origin : 'http://localhost:9001',
		methods : 'PUT, GET, POST, DELETE, OPTIONS',
		headers : 'Content-Type, Authorization, Accept'
	}
};

config.production = {
	database : {
		conStr : 'mongodb://' + process.env.OPENSHIFT_MONGODB_DB_USERNAME + ':' 
							+ process.env.OPENSHIFT_MONGODB_DB_PASSWORD + '@' 
							+ process.env.OPENSHIFT_MONGODB_DB_HOST + ':' 
							+ process.env.OPENSHIFT_MONGODB_DB_PORT + '/' 
							+ process.env.OPENSHIFT_APP_NAME
	},
	server : {
		ip : process.env.OPENSHIFT_NODEJS_IP,
		port : process.env.OPENSHIFT_NODEJS_PORT,
		name : 'http://nodejs-pizapi.rhcloud.com'
	},
	client : {
		origin : 'http://ristorante-pizapi.rhcloud.com',
		methods : 'PUT, GET, POST, DELETE, OPTIONS',
		headers : 'Content-Type, Authorization, Accept'
	}
};

module.exports = config;
