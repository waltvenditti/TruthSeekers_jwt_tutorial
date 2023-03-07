const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const fs = require("fs");
const fakeLocal = require("./fakeLocal.json");
const bodyParser = require("body-parser");
const path = require("path");
const passport = require("passport");
const { v4:uuidv4 } = require("uuid");
const localStrategy = require("passport-local").Strategy;
const users = require("./users.json");
const bcrypt = require("bcrypt");
const JWTstrategy = require("passport-jwt").Strategy;

// Setting view engine to ejs
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// So server can read body of req
app.use(bodyParser.urlencoded({extended:false}));

app.use(passport.initialize());

function getJwt() {
  console.log("in getJwt");
  // removes "Bearer" from token
  return fakeLocal.Authorization?.substring(7);
};

passport.use(
  // named "jwt", used in /secureroute
  new JWTstrategy(
    {
      secretOrKey: "TOP_SECRET",
      jwtFromRequest: getJwt,
    },
    async (token, done) => {
      console.log("in jwt strat. tokenL ", token);
      // 0. Don't even make it through the getJwt function check. No token.
      // (I think it means that if no token is received in jwtFromRequest, this async function is not even called)
      // prints unauthorized.

      // 0B. Invalid token: again doesn't make it into this function. Prints unauthorized. 

      // 1. Makes it into this function but gets app error (displays error msg. No redirecting).
      // We simulate an app error occuring in this func with an email of "tokenerror"
      if (token?.user?.email == "tokenerror") {
        let testError = new Error(
          "Something bad happened. We've simulated an app error in teh JWTstrategy callback for users with an email of 'tokenerror'."
        );
        return done(testError, false);
      }

      if (token?.user?.email == "emptytoken") {
        // 2. Some other reason for user to not exist. Pass false as user:
        // Displays "unauthorized". Doesn't allow the app to hit the next function in the chain.
        // We're simulating an empty user / no user coming from the JWT.
        return done(null, false);
      }

      // 3. successfully decoded and validated user:
      // adds the req.user, req.login, etc., properties to req, then calls the next function in the chain
      return done(null, token.user);
    }
  )
);

passport.use(
  "login",
  // This is where the username/pw is verified. Depending on match or not, may send back obj with user or not
  new localStrategy({usernameField: "email", passwordField: "password"}, async (email, password, done) => {
    console.log("login named");
    // done(null, userObject, {message: "Optional success/fail message"});
    // done(err) // application error
    // done(null, false, {message: "Unauthorized login credentials"}) // User input error when 2nd param is false

    try {
      if (email === "apperror") {
        throw new Error(
          "The app crashed. We have reported the issue."
        );
      }
      // for each user in users, check if user.email matches email submitted to asnyc func above
      const user = users.find((user) => user.email === email);
      if (!user) {
        return done(null, false, {message: "User not found"});
      }
      const passwordMatches = await bcrypt.compare(password, user.password);
      if (!passwordMatches) {
        return done(null, false, {message: "Invalid credentials"});
      }
      return done(null, user, {
        message: "You are logged in"
      });
    } catch (error) {
      return done(error);
    }
  })
);

passport.use(
  "signup",
  new localStrategy(
    {usernameField:"email", passwordField:"password"},
    async (email, password, done) => {
      try {
        if (password.length <= 4 || !email) {
          done(null, false, {message:"Your credentials do not match the criteria",});
        } else {
          const hashedPass = await bcrypt.hash(password, 10);
          let newUser = {email, password: hashedPass, id: uuidv4() };
          // users is imported at top, is initially an empty array in users.json
          users.push(newUser);
          // this saves the modified users array so that the user added persists in users.json
          await fs.writeFile("users.json", JSON.stringify(users), (err) => {
            if (err) return done(err);
            console.log("updated fake database");
          });
          return done(null, newUser, {message:"Signed up successfully"});
        }
      } catch (err) {
        return done(err);
      }
    }
  )
)

app.get("/", (req, res) => {
  res.send("Homepage");
});

app.get("/secureroute", 
passport.authenticate("jwt", {session:false}), async (req, res) => {
  console.log("req.isAuthenticated: ", req.isAuthenticated());
  console.log("req.user: ", req.user);
  console.log("req.login: ", req.login);
  console.log("req.logout: ", req.logout);
  res.send(`Welcome to the secure route ${req.user.email}`);
});

app.get("/logout", async (req, res) => {
  res.send("logged out");
});

app.get("/login", async (req, res) => {
  res.render("login");
});

app.get("/signup", async (req, res) => {
  res.render("signup");
});

app.get("/failed", (req, res) => {
  res.send(`failed ${req.query?.message}`);
});

app.get("/success", (req, res) => {
  res.send(`success ${req.query?.message}`);
});

// !!!!!
// !!!!!
// left off here at 1:14:27
// need to make logging in gen a token for user
app.post("/login", async (req, res, next) => {
  // "custom callback" strategy 
  passport.authenticate("login", async (error, user, info) => {
    if (error) {
      return next(error.message);
    }
    if (!user) {
      res.redirect(`/failed?message=${info.message}`);
    }
    if (user) {
      res.redirect(`/success?message=${info.message}`);
    }
  })(req, res, next);
});

app.post("/signup", async (req, res, next) => {
  passport.authenticate("signup", async function (error, user, info) {
    if (error) {
      return next(error);
    }
    if (!user) {
      res.redirect(`/failed?message=${info.message}`);
    }
    const body = { _id: user.id, email: user.email };
    console.log(body);
    const token = jwt.sign({ user: body}, "TOP_SECRET")
    await fs.writeFile("fakeLocal.json", JSON.stringify({ Authorization: `Bearer ${token}` }), (err) => {
      if (err) throw err;
    })
    res.redirect(`/success?message=${info.message}`);
  })(req, res, next);
})

app.listen(3000, () => {
  console.log("Listening on port 3000...")
});