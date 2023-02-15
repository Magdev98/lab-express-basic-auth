const router = require("express").Router();
const User = require("../models/User.model");
const bcrypt = require("bcryptjs");
const isAuthenticated = require("../middlewares/isAuthenticated");

// Iteration 1
router.get("/signup", async (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", async (req, res, next) => {
  const { username, password } = req.body;
  try {
    // condition to check that all fields are completed
    if (!username || !password) {
      return res.render("auth/signup", {
        errorMessage: "Don't forget to fill all the fields",
      });
    }

    if (password.length <= 8) {
      return res.render("auth/signup", {
        errorMessage: "It needs a longer password",
      });
    }

    // condition to check that username must be unique in our application and will identify each user + User.model => unique key
    const foundExistedUser = await User.findOne({ username: username });
    if (foundExistedUser) {
      return res.render("auth/signup", {
        errorMessage: "This username already exists",
      });
    }
    // password must be encrypted - hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const userToCreate = { username, password: hashedPassword };

    // sign up a user by adding it
    const userFromDb = await User.create(userToCreate);
    console.log(userFromDb);
    res.redirect("/login");
  } catch (error) {
    next(error);
  }
});

router.get("/login", async (req, res, next) => {
  res.render("auth/login");
});

// Iteration 2
router.post("/login", async (req, res, next) => {
  const { username, password } = req.body;
  try {
    if (!username || !password) {
      return res.render("auth/login", {
        errorMessage: "Don't forget to fill all the fields",
      });
    }

    const foundExistedUser = await User.findOne(
      { username },
      { password: 1, username: 1 }
    );
    if (!foundExistedUser) {
      return res.render("auth/login", {
        errorMessage: "Need to sign up first",
      });
    }

    const matchingPass = await bcrypt.compare(
      password,
      foundExistedUser.password
    );
    if (!matchingPass) {
      return res.render("auth/login", {
        errorMessage: "Invalid credentials!",
      });
    }

    req.session.currentUser = foundExistedUser;
    res.redirect("/profile");
  } catch (error) {
    next(error);
  }
});

router.get("/profile", isAuthenticated, (req, res, next) => {
  res.render("profile");
});

router.get("/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) {
      return next(error);
    }
    res.redirect("/login");
  });
});

module.exports = router;
