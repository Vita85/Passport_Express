const { ObjectId } = require("mongodb");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");

const { mongoInstance } = require("./dbConnect");

//Configure Local Strategy
function initialPassport(passport) {
  passport.use(
    new LocalStrategy(
      { usernameField: "email", passwordField: "password" },
      async (email, password, done) => {
        console.log("Login attempt for email:", email);
        try {
          const db = mongoInstance.getDB();
          const userCollection = db.collection("users");
          const user = await userCollection.findOne({ email });
          if (!user) {
            return done(null, false, { message: "User not found" });
          }

          const isMatch = await bcrypt.compare(password, user.password);
          if (!isMatch) {
            return done(null, false, { message: "Incorrectly entered data" });
          }

          console.log("User authenticated successfully");
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  //Serialize and Deserialize Users
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const db = mongoInstance.getDB();
      const userCollection = db.collection("users");
      
      const userId = new ObjectId(id);
      const user = await userCollection.findOne({ _id: userId });
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
}

module.exports = { initialPassport };
