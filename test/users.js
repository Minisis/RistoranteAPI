'use strict';

var app = require('./../app'),
		request = require('supertest'),
		should = require('should'),
		MongoClient = require('mongodb').MongoClient,
		async = require('async'),
		config = require('./../config'),
		users,
		dbConfig;

if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === undefined) {
	dbConfig = config.development.database;
}
if (process.env.NODE_ENV === 'production') {
	dbConfig = config.production.database;
}


function cleanDb (cb) {
	users.drop(function(err) {
		if (!err) return cb(null);
		if (err.errmsg !== 'ns not found') return cb(err);
		if (err.errmsg === 'ns not found') {
			return cb(null);
		}
		else {
			cb(null);
		}
	});
}

describe('Users Unit Test' , function() {
	before('Create DB connection' , function(done) {
		MongoClient.connect(dbConfig.conStr , function(err , db) {
			if (err) throw err;
			console.log('Database connection done');
				users = db.collection('users');
				done();
		});
	});
	after('After method' , function(done) {
		console.log('After method');
		done();
	});
	describe('#Create users /users POST' , function() {
		beforeEach('Dropping users collection' , function(done) {
			cleanDb(done);
		});
		it('Should create a new user' , function(done) {
			var newUser = {
				email : 'email@email.com',
				password : 'password',
				type : 'local'
			};
			request(app) 
				.post('/users')
				.send(newUser)
				.expect('Content-Type', /json/) 
				.expect('Location', /http:\/\/localhost:3000\/users\/([a-b0-9A-B]+)/)
				.expect(201)
				.end(function(err , res) { 
					should(err).not.be.ok;
					var body = res.body;
					var data = body.data;
					body.status.should.be.type('string');
					body.status.should.equal('success');
					body.code.should.be.type('number');
					body.code.should.equal(201);
					body.message.should.be.type('string');
					should(body.message).not.be.ok;
					data.should.be.type('object');
					data.token.should.be.an.Object;
					data.token.hash.should.be.a.String;
					data.token._id.should.be.a.String;
					data.token.createdDate.should.be.ok;
					data.id.should.be.type('string');
					data.id.should.be.not.be.empty;
					done();
				});
		});
		it('Should throw InvalidCredentials error when parameters are not valid' , function(done) {
			var newUser = {
				email : 'asd123',
				password : '12345',
				type : 'local'
			};
			request(app)
				.post('/users')
				.send(newUser)
				.expect('Content-Type' , /json/)
				.expect(400)
				.end(function(err , res) {
					var body = res.body;
					var data = body.data;
					should(err).not.be.ok;
					body.status.should.be.type('string');
					body.status.should.equal('error');
					body.code.should.be.type('number');
					body.code.should.equal(400);
					body.message.should.be.type('string');
					body.message.should.equal('invalid username or password');
					data.should.be.type('string');
					data.should.be.equal('InvalidCredentials');
					done();
				});
		});
	});
	describe('#Read users /users GET' , function() {
		beforeEach('Create 10 new users' , function(done) {
			cleanDb(function(err) {
				if (err) return done(err);
				var users = [],
						i = 0;
				for (i ; i < 10 ; i += 1) {
					users.push({ email : 'email' + i + '@gmail.com',
										 	 password : 'password',
											 type : 'local' });
				}
				async.each(users , function(user , callback) {
					request(app)
						.post('/users')
						.send(user)
						.end(function(err , res) {
							if (err) return callback(err);
							var body = res.body;
							callback();
						});
				},
				function(err) {
					if (err) throw err;
					done();	
				});
			});
		});
		it('Should return 10 users' , function(done) {
			request(app)
				.get('/users')
				.expect('Content-Type' , /json/)
				.expect(200)
				.end(function(err , res) {
					var body  = res.body;
					should(err).not.be.ok;
					body.status.should.be.type('string');
					body.status.should.equal('success');
					body.code.should.be.type('number');
					body.code.should.equal(200);
					body.message.should.be.type('string');
					body.message.should.be.empty;
					body.data.should.be.an.Array;
					body.data.should.have.length(10)
					done();
				});
		});
	});
	describe('#Read by ID /users/:id' , function() {
		beforeEach('Cleaning DB' , function(done) {
			cleanDb(done);
		});
		it('Should read the information of a user by id' , function(done) {
			var newUser = {
				email : 'asd123@gmail.com',
				password : '12345',
				type : 'local'
			};
			request(app)
				.post('/users')
				.send(newUser)
				.end(function(err , res) {
					var userId = res.body.data.id;
					if (err) return done(err);
					request(app)
						.get('/users/' + userId)
						.expect('Content-Type' , /json/)
						.expect(200)
						.end(function(err , res) {
							var body = res.body;
							should(err).not.be.ok;
							body.status.should.be.type('string');
							body.status.should.equal('success');
							body.code.should.be.type('number');
							body.code.should.equal(200);
							body.message.should.be.type('string');
							body.message.should.be.empty;
							body.data.should.be.an.Object;
							body.data.should.have.property('id');
							body.data.should.have.property('email');
							//body.data.should.have.property('first');
							//body.data.should.have.property('last');
							done();		
						});
				});
		});
		it('Should return an InvalidParameter error' , function(done) {
			request(app)
				.get('/users/foo')
				.expect('Content-Type' , /json/)
				.expect(404)
				.end(function(err , res) {
					var body = res.body;
					should(err).not.be.ok;
					body.status.should.be.type('string');
					body.status.should.equal('error');
					body.code.should.be.type('number');
					body.code.should.equal(404);
					body.data.should.be.type('string');
					body.data.should.match(/InvalidParameter/);
					body.message.should.be.a.String;
					body.message.should.match(/id invalid or not found/);
					done();
				});
		});
	});
	describe('#Update by id /users PUT' , function() {
		beforeEach('Cleaning DB' , function(done) {
			cleanDb(done);
		});
		it('Should update a user by id' , function(done) {
			var nUser = {
				email : 'example@gmail.com',
				password : '12345',
				type : 'local'
			};
			request(app)
				.post('/users')
				.send(nUser)
				.expect('Content-Type' , /json/)
				.expect(201)
				.end(function(err , res) {
					var id = res.body.data.id,
							uUser = {
								first : 'luis',
								last : 'valdovinos'
							};
					should(err).not.be.ok;
					request(app)
						.put('/users/' + id)
						.send(uUser)
						.expect('Content-Type' , /json/)
						.expect(200)
						.end(function(err , res) {
							var body = res.body;
							should(err).not.be.ok;
							body.status.should.be.type('string');
							body.status.should.equal('success');
							body.code.should.be.type('number');
							body.code.should.equal(200);
							body.data.should.be.an.Object;
							body.data.id.should.be.ok;
							body.message.should.be.a.String;
							body.message.should.be.empty;
							done();	
						});
				});
		});
		it('Should return an InvalidParameter error' , function(done) {
			request(app)
				.put('/users/foo')
				.expect('Content-Type' , /json/)
				.expect(404)
				.end(function(err , res) {
					var body = res.body;
					should(err).not.be.ok;
					body.status.should.be.type('string');
					body.status.should.equal('error');
					body.code.should.be.type('number');
					body.code.should.equal(404);
					body.data.should.be.type('string');
					body.data.should.match(/InvalidParameter/);
					body.message.should.be.a.String;
					body.message.should.match(/id invalid or not found/);
					done();
				});
		});
		it('Should return an InvalidBody error' , function(done) {
			var nUser = {
				email : 'example@gmail.com',
				password : '12345',
				type : 'local'
			};
			request(app)
				.post('/users')
				.send(nUser)
				.expect('Content-Type' , /json/)
				.expect(201)
				.end(function(err , res) {
					var id = res.body.data.id,
							uUser = {
								email : 'lastkiss@gm--',
								first : 123123,
								last : '!@#!@#!@'
							};
					should(err).not.be.ok;
					request(app)
						.put('/users/' + id)
						.send(uUser)
						.expect('Content-Type' , /json/)
						.expect(400)
						.end(function(err , res) {
							var body = res.body;
							should(err).not.be.ok;
							body.status.should.be.type('string');
							body.status.should.equal('error');
							body.code.should.be.type('number');
							body.code.should.equal(400);
							body.data.should.be.a.String;
							body.data.should.match(/InvalidBody/);
							body.message.should.be.a.String;
							body.message.should.match(/first|last|email is invalid/);
							done();	
						});
				});
		});
	});
	describe('#Delete by ID /users/:id' , function() {
		beforeEach('Cleaning DB' , function(done) {
			cleanDb(done);
		});
		it('Should delete a user by id' , function(done) {
			var newUser = {
				email : 'asd123@gmail.com',
				password : '12345',
				type : 'local'
			};
			request(app)
				.post('/users')
				.send(newUser)
				.end(function(err , res) {
					var userId = res.body.data.id;
					if (err) return done(err);
					request(app)
						.delete('/users/' + userId)
						.expect('Content-Type' , /json/)
						.expect(200)
						.end(function(err , res) {
							var body = res.body;
							should(err).not.be.ok;
							body.status.should.be.type('string');
							body.status.should.equal('success');
							body.code.should.be.type('number');
							body.code.should.equal(200);
							body.message.should.be.type('string');
							body.message.should.be.empty;
							body.data.should.be.an.Object;
							body.data.should.have.property('id');
							body.data.should.have.property('email');
							//body.data.should.have.property('first');
							//body.data.should.have.property('last');
							request(app)
								.get('/users')
								.expect('Content-Type' , /json/)
								.expect(200)
								.end(function(err , res) {
									var body = res.body;
									should(err).not.be.ok;
									body.status.should.be.a.String;
									body.status.should.be.equal('success');
									body.code.should.be.a.Number;
									body.code.should.equal(200);
									body.message.should.be.a.String;
									body.message.should.be.empty;
									body.data.should.be.an.Array;
									body.data.should.be.empty;
									done();		
								});
						});
				});
		});
		it('Should return an InvalidParameter error' , function(done) {
			request(app)
				.delete('/users/foo')
				.expect('Content-Type' , /json/)
				.expect(404)
				.end(function(err , res) {
					var body = res.body;
					should(err).not.be.ok;
					body.status.should.be.type('string');
					body.status.should.equal('error');
					body.code.should.be.type('number');
					body.code.should.equal(404);
					body.data.should.be.type('string');
					body.data.should.match(/InvalidParameter/);
					body.message.should.be.a.String;
					body.message.should.match(/id invalid or not found/);
					done();
				});
		});
	});
});
