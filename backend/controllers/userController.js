const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
// const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

// @desc    Register new user
// @route   POST /api/users
// @access  Public
const registerUser = async (req, res) => {
try{

  if (req.body == null) {
    throw new Error("Please add all fields");
  }
  res.status(400);
  // Check if user exists
  const userExists = await User.findOne({ email : req.body.email });
  
  if (userExists) {
    res.status(400);
    throw new Error("User already exists");
  }
  
  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);
  
  // Create user
  let user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  }); //
  user = await user.save();
  
  const token = generateToken(user.email);
  
  if (!user) {
    res.status(400);
    throw new Error("Invalid user data");
  } else {
    res.json(user, {token: token});
  }
}
catch(e){
  res.status(401).json(e.message)
}
}

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
const loginUser = async (req, res) => {
  const { email, password } = req.body

  // Check for user email
  const user = await User.findOne({ email })

  if (user && (await bcrypt.compare(password, user.password))) {
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    })
  } else {
    res.status(400)
    throw new Error('Invalid credentials')
  }
}

// @desc    Get user data
// @route   GET /api/users/me
// @access  Private
const getMe = async (req, res) => {
  res.status(200).json(req.user)
}

// Generate JWT
const generateToken = (email) => {
  return jwt.sign({ email }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  })
}

module.exports = {
  registerUser,
  loginUser,
  getMe,
}
