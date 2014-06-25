
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
var flash = require('express-flash');

passport.use(new LocalStrategy(function (username, password, done){
	User.findOne({username: username}, function (err, user){
		if (err) return done(err);
		if (!user) return done(null, false, {message: "Incorrect username"});
			user.comparePassword(password, function (err, isMatch){
				if(isMatch){
					return done(null, user);
				} else {
					return done(null, false, { message:"Incorrect password"});
				}
			});
	});
}));

passport.serializeUser(function (user, done){
	done(null, user.id);
});

passport.deserializeUser(function (id, done){
	User.findById(id, function (err, user){
		done(err, user);
	});
});

var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

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
};
var User = mongoose.model('User', userSchema);


var app = express();
mongoose.connect('localhost');

// all Middleware
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({secret: 'session secret key'}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));


//Routes
app.get('/', function (req, res){
	res.render('index', { 
		title: 'Express',
		user: req.user
	});
});

app.get('/login', function (req, res){
	res.render('login', {
		user: req.user
	});
});

app.post('/login', function (req, res, next){
	passport.authenticate('local', function (err, user, info){
		if (err) return next (err)
			if (!user) {
				return res.redirect('/login')
			}
			req.logIn(user, function (err){
				if (err) return next(err);
				return res.redirect('/');
			});
	})(req, res, next);
});

app.get('/signup', function (req, res){
	res.render('signup', {
		user: req.user
	});
});

app.post('/signup', function (req, res){
	var user = new User({
		username: req.body.username,
		email: req.body.email,
		password: req.body.password
	});

	user.save(function (err){
		req.logIn(user, function(err){
			res.redirect('/');
		});
	});
});

app.get('/logout', function (req, res){
	req.logout();
	res.redirect('/');
});

app.get('/forgot', function (req, res){
	res.render('forgot', {
		user: req.user
	});
});

app.post('/forgot', function (req, res, next){
	async.waterfall([
		function (done){
			crypto.randomBytes(20, function (err, buf){
				var token = buf.toString('hex');
				done(err, token);
			});
		},

		function (token, done){
			User.findOne({email: req.body.email}, function (err, user){
				if (!user){
					req.flash('error', 'No account with this email address exists');
					return res.redirect('/forgot');
				}

				user.resetPasswordToken = token;
				user.resetPasswordExpires = Date.now() + 3600000;

				user.save(function (err){
					done (err, token, user);
				});
			});
		},

		function (token, user, done){
			var smtpTransport = nodemailer.createTransport('SMTP', {
				service: 'SendGrid',
				auth: {
					user: '!!! YOUR SENDGRID USERNAME !!!',
					pass: '!!! YOUR SENDGRID PASSWORD !!!'
				}
			});
			var mailOptions = {
				to: user.email, 
				from: 'passwordreset@demo.com',
				subject: 'Node.js Password Reset',
				text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
			};

			smtpTransport.sendMail(mailOptions, function (err){
				req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
				done(err, 'done');
			});
		}
		], function(err){
			if (err) return next(err);
			res.redirect('/forgot');
		});
});

app.get('/reset/:token', function (req, ress){
	User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now()}}, function (err, user){
		if (!user){
			req.flash('error', 'Password reset token is invalid or has expired');
			return res.redirect('/forgot');
		}
		res.render('reset', {
			user: req.user
		});
	});
});

app.post('/reset/:token', function (req, res){
	async.waterfall([
		function (done){
			User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now()}}, function (err, user){
				if (!user){
					req.flash('error', 'Password reset token is invalid or has expired');
					return res.redirect('back');
				}

				user.password = req.body.password;
				user.resetPasswordToken = undefined;
				user.resetPasswordExpires = undefined;

				user.save(function (err){
					req.logIn(user, function (err){
						done(err, user);
					});
				});
			});
		},

		function (user, done){
			var smtpTransport = nodemailer.createTransport('SMTP', {
				service: 'SendGrid',
				auth: {
					user: '!!! YOUR SENDGRID USERNAME !!!',
					pass: '!!! YOUR SENDGRID PASSWORD !!!'
				}
			});

			var mailOptions = {
				to: user.email,
        		from: 'passwordreset@demo.com',
        		subject: 'Your password has been changed',
        		text: 'Hello,\n\n' +
          			'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      			};
      			smtpTransport.sendMail(mailOptions, function (err){
      				req.flash('success', 'Success! your password has been changed');
      				done(err);
      			});
			}

		], function (err){
			res.redirect('/');
		});
});

http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});