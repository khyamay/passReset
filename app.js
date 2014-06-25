
/**
 * Module dependencies.
 */

var express = require('express');
var http = require('http');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var mongoose = require('mongoose');
var nodemailer = require('nodemailer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');

var app = express();
mongoose.connect('localhost');

// all environments
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({secret: 'session secret key'}));
app.use(express.static(path.join(__dirname, 'public')));


var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

var User = mongoose.model('User', userSchema);
userSchema.pre('save', function (next){
	var user = this;
	var SALT_FACTOR = 5;

	if(!user.isModified('password')) return next();

	bcrypt.genSalt(SALT_FACTOR, function (err, salt){
		if (err) return next(err);

		bcrypt.hash(user.password, salt, null, function (err, hash){
			if (err) return next(err);
			user.password = hash;
			next();
		});
	});
});

userSchema.methods.comparePassword = function (candidatePassword, cb){
		bcrypt.compare(candidatePassword, this.password, function (err, isMatch){
			if (err) return cb(err);
			cb(null, isMatch);
	});
}





app.get('/', function (req, res){
	res.render('index', { title: 'Express'});
});


http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});