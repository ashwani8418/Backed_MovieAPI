const CustomError = require("../Utils/CustomError");
const sendEmail = require("../Utils/email");
const User = require("./../Models/userModel");
const asyncErrorHandler = require("./../Utils/asyncErrorHandler");
const jwt = require("jsonwebtoken");
const util = require("util");
const crypto = require("crypto");

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

exports.restrict = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      const error = new CustomError(
        "You do not have permission to perform this action",
        403
      );
      next(error);
    }
    next();
  };
};

// for multiple role
// exports.restrict = (...role) => {
//   return (req, res, next) => {
//     if (!role.includes(req.user.role)) {
//       const error = new CustomError(
//         "You do not have permission to perform this action",
//         403
//       );
//       next(error);
//     }
//     next();
//   };
// };

exports.forgotPassword = asyncErrorHandler(async (req, res, next) => {
  // 1. Get the user based on posted email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    const error = new CustomError(
      "We could not find the user with the given eamil",
      404
    );
    next(error);
  }
  // 2. Generate a random reset token
  const resetToken = user.createResetPasswordToken();
  await user.save({ validateBeforeSave: false });

  // 3.Send the token back to the user email
  const resetURL = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/resetPassword/${resetToken}`;
  const message = `We have received a password reset request. Please use the below link to reset your password \n\n ${resetURL}\n\nThis reset password link will be valid only for 10 minutes`;
  try {
    await sendEmail({
      email: user.email,
      subject: "Password reset request received",
      message: message,
    });
    res.status(200).json({
      status: "success",
      message: "password reset link send to the user email",
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpires = undefined;
    user.save({ validateBeforeSave: false });

    return next(
      new CustomError(
        "There was an error in sending password reset email. Please try again later",
        500
      )
    );
  }
});

exports.resetPassword = asyncErrorHandler(async (req, res, next) => {
  // 1. if the user exists with the given token & token has not expired
  const token = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");
  const user = await User.findOne({
    passwordResetToken: token,
    passwordResetTokenExpires: { $gt: Date.now() },
  });

  if (!user) {
    const error = new CustomError("Token is invalid or has expired", 400);
    next(error);
  }

  // 2. Reseting the USER Password
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordResetToken = undefined;
  user.passwordResetTokenExpires = undefined;
  user.passwordChangedAt = Date.now();

  user.save();

  // 3. Login the USER
  const loginToken = signToken(user._id);
  res.status(200).json({
    status: "success",
    loginToken,
  });
});
