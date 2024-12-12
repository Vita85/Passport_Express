require("dotenv").config();
const express = require("express");
const passport = require("passport");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");

const { mongoInstance } = require("./dbConnect");
const { initialPassport } = require("./passport");

const app = express();

const PORT = process.env.PORT || 8000;
const SECRET = process.env.SECRET_KEY;

mongoInstance
  .connectDB()
  .then(() => {
    console.log("Connect DB");
  })
  .catch((error) => {
    console.log("Error connect DB", error);
  });

// middleware parse JSON and URL
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Use session middleware
app.use(
  session({
    secret: SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false },
  })
);

// Initialize Passport
initialPassport(passport);
app.use(passport.initialize());
app.use(passport.session());

//Registered
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const db = mongoInstance.getDB();
    const usersCollection = db.collection("users");

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User exists." });
    }

    //hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    //create new user
    const newUser = {
      name,
      email,
      password: hashedPassword,
    };
    await usersCollection.insertOne(newUser);
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.log("Error user registering ", error);
    res.status(500).json({ message: "Error user registering " });
  }
});

//login
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/protected",
    failureRedirect: "/login",
  })
);

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect("/protected");
  }
  res.send("Login page");
});

//protected
app.get("/protected", (req, res) => {
  if (req.isAuthenticated()) {
    res.send("This is a protected route!");
  } else {
    res.redirect("/login");
  }
});

//logout
app.post("/logout", (req, res) => {
  req.logout((error) => {
    if (error) {
      return res.status(500).json({ message: "Error logging out" });
    }
    res.redirect("/login");
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
