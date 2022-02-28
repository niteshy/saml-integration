const passport = require("passport");
const passportSaml = require("passport-saml");
const passportJwt = require("passport-jwt");
const config = require("./config.json")[process.env.NODE_ENV || "dev"];
const JWT_SECRET = require('./secret');

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

// JWT strategy for passport
const JwtStrategy = new passportJwt.Strategy({
    jwtFromRequest: function (req) {
      // tell passport to read JWT from cookies
      let token = null;
      if (req && req.cookies && req.cookies["jwt"]) {
        token = req.cookies["jwt"];
        console.log("JWTStrategy: Token found in cookie");
      }
      console.log("JWTStrategy: token = ", token);
      return token;
    },
    secretOrKey: JWT_SECRET,
  },
  function (jwt_payload, done) {
    console.log("JWTStrategy: jwt_payload = ", jwt_payload.data); // called everytime a protected URL is being served
    return done(null, jwt_payload.data);
  }
);

// SAML strategy for passport -- Single IPD
const SamlStrategy = new passportSaml.Strategy({
    issuer: config.auth.issuer,
    path: "/login/callback",
    entryPoint: config.auth.entryPoint,
    cert: config.auth.cert,
  },
  function (profile, done) {
    console.log("SamlStrategy: start");
    console.log(profile);
    if (!profile.Email) {
      return done(new Error("No email found"), null);
    }
    let user = findByEmail(profile.Email);
    if (!user) {
      users.push(profile);
      console.log("Adding profile to users")
      return done(null, profile);
    }
    console.log("SamlStrategy: end");
    return done(null, user);
  }
);

passport.use(SamlStrategy);
passport.use(JwtStrategy);

passport.protected = passport.authenticate('jwt', { session: false, failureRedirect: '/unauthorized' });

module.exports = passport;
