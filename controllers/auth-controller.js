const User = require('../models/user');
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');

const register = async (req, res, next) => {
  const { name, email, password } = req.body;

  try{
    const user = await User.create({
      name,
      email,
      password
    });

    res.status(200).json({success: true});
  }
  catch(err){
    next(err);
  }
}

const login = async (req, res, next) => {
  const { email, password } = req.body;

  // Check if email and password is provided
  if(!email || !password){
    return res.status(400).json({message: "Please provide an email and password!"})
  }

  try{
    // Check that user exists by email
    const user = await User.findOne({ email }).select("+password");

    if(!user){
      return res.status(401).json({message: "Invalid credentials!"})
    }

    // Check that password match
    const isMatch = await user.matchPassword(password);

    if(!isMatch){
      return res.status(401).json({message: "Invalid credentials!"})
    }

    console.log(user.getSignedJwtToken())
    const token = user.getSignedJwtToken();
    const userId = user.id
    res.status(200).json({success: true, token, userId});

  }
  catch(err){
    next(err);
  }
}

const forgotPassword = async (req, res, next) => {
  const { email } = req.body;

  try{
    const user = await User.findOne({email});
    if(!user){
      return res.status(404).json({success: false, message: "No email could not be sent"});
    }

    // Reset Token Gen and add to database hashed (private) version of token
    const resetToken = user.getResetPasswordToken();

    await user.save();

    // Create reset url to email to provided email
    let resetUrl;
    if(process.env.NODE_ENV === "development"){
      resetUrl = `http://localhost:3000/passwordreset/${resetToken}`;
    }
    else{
      resetUrl = `https://ty-course-review.herokuapp.com/passwordreset/${resetToken}`;
    }

    // HTML Message
    const message = `
      <h1>You have requested a password reset</h1>
      <p>Please make a put request to the following link:</p>
      <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
    `;

    try {
      sendEmail({
        to: user.email,
        subject: "Password Reset Request",
        text: message,
      });

      res.status(200).json({ success: true, message: "Email Sent" });
    } catch (err) {
      console.log(err);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;

      await user.save();

      res.status(500).json({ success: false, message: "Email could not be sent" });
    }

  }
  catch(err){
    next(err);
  }
}

const resetPassword = async (req,res, next) => {
  // Compare token in URL params to hashed token
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.resetToken)
    .digest("hex");

  try {
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if(!user){
      return res.status(400).json({ 
        success: false, 
        message: "Invalid token"
      });
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.status(201).json({
      success: true,
      message: "Password updated success",
      token: user.getSignedJwtToken(),
    })
  }
  catch(err){
    next(err);
  }
  
}

const getProfile = async(req, res, next) => {
  User.findById(req.user.id)
    .select('-password')
    .then(user => res.status(200).json(user))
    .catch(err => res.status(404).json({error: 'profile not found'}))
}

const updateProfile = async(req, res, next) => {
  const { name, email } = req.body;

  // Check if name and email are provided
  if(!name || !email){
    return res.status(400).json({message: "Please provide a name and email!"})
  }

  try{
    // Check that user exists by email
    const user = await User.findOne({ email });

    if(!user){
      return res.status(401).json({message: "Invalid credentials!"})
    }

    const updateDoc = await User.findOneAndUpdate(
      { email: email},
      { name: name},
      { new: true}
    )
    res.status(200).json({message: "Update success!"});  
    
  }
  catch(err){
    next(err);
  }
}

module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword,
  getProfile,
  updateProfile
}