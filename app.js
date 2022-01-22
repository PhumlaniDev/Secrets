require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const findOrCreate = require("mongoose-findorcreate");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();

app.use(express.static("pubic"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: false }));

app.use(
	session({
		secret: "My little secret.",
		resave: false,
		saveUninitialized: false,
	})
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(
	`mongodb+srv://admin-phumlani:${process.env.DB_PSWD}@cluster0.jt1kf.mongodb.net/secrets?retryWrites=true&w=majority`,
	{
		useNewUrlParser: true,
	}
);

const userSchema = new mongoose.Schema({
	email: String,
	password: String,
	googleId: String,
	secret: String,
});

userSchema.plugin(passportLocalMongoose, { usernameField: "email" });
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});

// Google OAuth strategy
passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.CLIENT_ID,
			clientSecret: process.env.CLIENT_SECRET,
			callbackURL: "http://localhost:3000/auth/google/secrets",
			userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
		},
		function (accessToken, refreshToken, profile, cb) {
			User.findOrCreate({ googleId: profile.id }, function (err, user) {
				return cb(err, user);
			});
		}
	)
);

app.get("/", (req, res) => {
	res.render("home");
});

app.get(
	"/auth/google",
	passport.authenticate("google", { scope: ["profile"] })
);

app.get(
	"/auth/google/secrets",
	passport.authenticate("google", { failureRedirect: "/login" }),
	function (req, res) {
		// Successful authentication, redirect home.
		res.redirect("/secrets");
	}
);

app.get("/login", (req, res) => {
	res.render("login");
});

app.post("/login", (req, res) => {
	const user = new User({
		email: req.body.email,
		password: req.body.password,
	});

	req.login(user, (err) => {
		if (err) {
			console.log(err);
		} else {
			passport.authenticate("local")(req, res, () => {
				res.redirect("/secrets");
				console.log("user is successfully authenticated");
			});
		}
	});
});

app.get("/register", (req, res) => {
	res.render("register");
});

app.get("/secrets", (req, res) => {
	User.find({ secret: { $ne: null } }, (err, foundUser) => {
		if (err) {
			console.log(err);
		} else {
			if (foundUser) {
				res.render("secrets", { userWithSecrets: foundUser });
			}
		}
	});
});

app.get("/submit", (req, res) => {
	// Check if the user is authenticated
	if (req.isAuthenticated()) {
		res.render("submit");
	} else {
		res.redirect("/login");
	}
});

app.post("/submit", (req, res) => {
	const submittedSecret = req.body.secret;

	User.findById(req.user, (err, foundUser) => {
		if (err) {
			console.log(err);
		} else {
			if (foundUser) {
				foundUser.secret = submittedSecret;
				foundUser.save(() => {
					res.redirect("/secrets");
				});
			}
		}
	});
});

app.get("/logout", (req, res) => {
	// Check if the user is authenticated
	req.logOut();

	res.redirect("/");
});

app.post("/register", (req, res) => {
	// Register the user

	let email = req.body.email;
	let password = req.body.password;

	User.register({ email: email }, password, (err, user) => {
		if (err) {
			console.log(err);
			res.redirect("/register");
		} else {
			// Authenticate the user
			passport.authenticate("local")(req, res, () => {
				res.redirect("/secrets");
				console.log("user is successfully authenticated");
			});
		}
	});
});

app.listen(3000, () => {
	console.log("Server started at PORT 3000");
});
