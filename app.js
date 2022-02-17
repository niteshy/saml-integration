const bodyParser = require('body-parser');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const express = require('express');
const helmet = require('helmet');
const path = require('path');
const Saml2js = require('saml2js');

const session = require('express-session')

const auth = require('./auth');

const app = express();
app.use(cors());

app.use(bodyParser.json({limit: '10mb'}));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(helmet());
app.use(compression()); //Compress all routes

app.use(session({ secret: "application session" }));
app.use(auth.initialize());
app.use(auth.session());
app.use(express.static('public'));

//Get Methods
app.get('/', auth.protected, function(req, res) {
  res.sendFile(__dirname + '/index.html');
});

app.get('/home', auth.protected, function(req, res) { 
  console.log('going home');
  res.sendFile(__dirname + '/index.html');
});

//auth.authenticate check if you are logged in
app.get('/login', 
  auth.authenticate('saml', { 
    successRedirect: '/',
    failureRedirect: '/login', 
    failureFlash: true 
  }), function(req, res) {
    res.redirect('/');
  }
);

app.post('/login', 
  auth.authenticate('saml', { 
    failureRedirect: '/', 
    failureFlash: true 
  }), function(req, res, next) {
    const xmlResponse = req.body.SAMLResponse;
    const parser = new Saml2js(xmlResponse);
    req.samlUserObject = parser.toObject();
    res.redirect('/home');
    next();
});

//POST Methods, redirect to home successful login
app.post('/login/callback', 
  auth.authenticate('saml', { 
    failureRedirect: '/', 
    failureFlash: true 
  }), function(req, res, next) {
    const xmlResponse = req.body.SAMLResponse;
    const parser = new Saml2js(xmlResponse);
    req.samlUserObject = parser.toObject();
    res.redirect('/home');
    next();
});

//code for importing static files
app.use(express.static(path.join(__dirname, 'public')));
const currentPort = process.env.PORT || 3000;
app.listen(currentPort);
console.log("Server started at PORT " + currentPort);
