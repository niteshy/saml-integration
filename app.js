const bodyParser = require("body-parser");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const express = require("express");
const helmet = require("helmet");
const path = require("path");
const Saml2js = require("saml2js");
const { sign } = require("jsonwebtoken");
const JWT_SECRET = require("./secret");

const auth = require("./auth");

const app = express();

app.use(cors());
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(helmet());
app.use(compression()); //Compress all routes

app.use(auth.initialize());
app.use(express.static("public"));

const reqLogger = function (req, res, next) {
  console.log(`Request: ${req.url} ${req.method} `, req.query, req.params);
  next()
}
app.use(reqLogger);

//Get Methods
app.get("/", function (req, res) {
  res.sendFile(__dirname + "/pages/index.html");
});

app.get("/unauthorized", function (req, res) {
  res.sendFile(__dirname + "/pages/unauthorized.html");
});

app.get("/home", auth.protected, function (req, res) {
  res.sendFile(__dirname + "/pages/home.html");
});

//auth.authenticate check if you are logged in
app.get("/login/sso",
  auth.authenticate("saml", {
    successRedirect: "/",
    failureRedirect: "/login/sso",
    failureFlash: true,
  }),
  function (req, res) {
    console.log(`/login/sso`)
    res.redirect("/");
  }
);

//POST Methods, redirect to home successful login
app.post("/login/sso/callback",
  auth.authenticate("saml", {
    failureRedirect: "/",
    failureFlash: true,
  }),
  function (req, res) {
    const xmlResponse = req.body.SAMLResponse;
    const parser = new Saml2js(xmlResponse);
    const profile = parser.toObject();

    req.samlUserObject = profile;
    const token = sign({
        data: profile,
      }, 
      JWT_SECRET,
      { expiresIn: 600 }
    );
    res.cookie("jwt", token);
    console.log("On sso/callback token = ", token);
    res.redirect("/home");
  }
);

const currentPort = process.env.PORT || 3000;
app.listen(currentPort);
console.log("Server started at PORT " + currentPort);
