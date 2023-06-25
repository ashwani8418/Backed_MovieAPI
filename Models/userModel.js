const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");

//name, email, password, confirmPassword, photo
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please enter your name."],
  },
  email: {
    type: String,
    required: [true, "Please enter an email."],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, "Please enter a valid email."],
  },
  photo: String,

  password: {
    type: String,
    required: [true, "Please enter a password."],
    minlength: 8,
    select: false,
  },
  confirmPassword: {
    type: String,
    required: [true, "Please confirm your password."],
    validate: {
      // This validator will only work for save() & create()
      validator: function (val) {
        return val == this.password;
      },
      message: "Password & Confirm Password does not match!",
    },
  },

  passwordChangedAt: Date,
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  this.password = await bcrypt.hashSync(this.password, 10);
  this.confirmPassword = undefined;
  next();
});

userSchema.methods.comparePasswordInDb = async function (pswd, pswdDB) {
  return bcrypt.compareSync(pswd, pswdDB);
};

userSchema.methods.isPasswordChanged = async function(JWTTimestamp){
  if(this.passwordChangedAt){
    const psswdChangeTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    console.log(psswdChangeTimestamp, JWTTimestamp);
    return JWTTimestamp < psswdChangeTimestamp;
  }
  return false;
};


const User = mongoose.model("User", userSchema);

module.exports = User;
