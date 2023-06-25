const CustomError = require("../Utils/CustomError");
const User = require("./../Models/userModel");
const asyncErrorHandler = require("./../Utils/asyncErrorHandler");
const jwt = require("jsonwebtoken");
const util = require("util");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_STR, {
    expiresIn: process.env.LOGIN_EXPIRES,
  });
};
exports.signup = asyncErrorHandler(async (req, res, next) => {
  const newUser = await User.create(req.body);
  res.status(201).json({
    status: `success`,
    data: {
      user: newUser,
    },
  });
});

exports.login = asyncErrorHandler(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    const error = new CustomError(
      "Please provide email & password for log in!",
      400
    );
    return next(error);
  }

  //   Check if the user exist in the database with given email
  const user = await User.findOne({ email }).select("+password");

  //   const isMatch = user.comparePasswordInDb(password, user.password);
  if (!user || !(await user.comparePasswordInDb(password, user.password))) {
    const error = new CustomError("Incorrect email or Password", 400);
    return next(error);
  }
  const token = signToken(user._id);
  res.status(200).json({
    status: "success",
    token,
  });
});

exports.protect = asyncErrorHandler(async function (req, res, next) {
  // 1. Read the token & check if it exist
  const testToken = req.headers.authorization || req.headers.Authorization;
  let token;
  if (testToken && testToken.startsWith("Bearer")) {
    token = testToken.split(" ")[1];
    console.log(token);
  }
  if (!token) {
    return next(new CustomError("You are not logged in", 401));
  }

  // 2. Validate the token
  const decodedToken = await util.promisify(jwt.verify)(
    token,
    process.env.SECRET_STR
  );

  // 3.If the user exist

  const user = await User.findById(decodedToken.id);

  console.log(user);
  if (!user) {
    const error = new CustomError(
      "The user with given token does not exist",
      401
    );
    next(error);
  }
  // 4. If the user changed password after teh token was issued
  if (await user.isPasswordChanged(decodedToken.iat)) {
    const error = new CustomError(
      "The password has been changed recently. Please login again",
      401
    );
    return next(error);
  }

  // 5. Allow user to access route
  req.user = user;
  next();
});
