const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const userSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: [true, "Please provide email address"],
    unique: true,
    validate: [validator.isEmail, 'Please provide an valid email']
  },
  password: {
    type: String,
    required: [true, "Please add a password"],
    minlength: 6,
    select: false
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date
});

userSchema.pre('save', async function (next){
  if (!this.isModified("password")) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
})

userSchema.methods.matchPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.getSignedJwtToken = function (){
  console.log('ID : ',this._id)
  return jwt.sign({id: this._id}, 'abc',{
    expiresIn: 24*360000
  });
}

userSchema.methods.getResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(20).toString("hex");

  // Hash token (private key) and save to database
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Set token expire date
  this.resetPasswordExpire = Date.now() + 10 * (60 * 1000); // Ten Minutes
  
  return resetToken;
}

module.exports = mongoose.model('User',userSchema);