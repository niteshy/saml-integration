
const passport = require('passport');
const passportSaml = require('passport-saml');
const config = require('./config.json')[process.env.NODE_ENV || 'dev'];

let users = [];

function findByEmail(email) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.Email === email) {
      return user;
    }
  }
  return null;
}

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// SAML strategy for passport -- Single IPD
const strategy = new passportSaml.Strategy({
    issuer: config.auth.issuer,
    path: '/login/callback',
    entryPoint: config.auth.entryPoint,
    cert: config.auth.cert
  },
  function(profile, done) {
    console.log('Succesfully authenticated profile');
    console.log(profile);
    if (!profile.Email) {
      return done(new Error("No email found"), null);
    }
    let user = findByEmail(profile.Email);
    if (!user) {
      console.log(`profile = `, profile)
      users.push(profile);
      return done(null, profile);
    }
    console.log('Ending Method for profiling');
    return done(null, user);
  });

passport.use(strategy);

passport.protected = function prot(req, res, next) {
  console.log('login status: ' + req.isAuthenticated());
  if (req.isAuthenticated()) {
    return next();
  }
  console.log('login please: ' + req.isAuthenticated());
  res.redirect('/login');
};

module.exports = passport;
