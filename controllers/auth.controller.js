const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const logger = require("../config/logger");

const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res
      .status(201)
      .json({ message: "User registered successfully", userId: newUser._id });
  } catch (error) {
    logger.error(`Error in register: ${error.message}`);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const accessToken = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRATION }
    );
    const refreshToken = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRATION }
    );

    res.status(200).json({
      accessToken,
      refreshToken,
      expiresIn: process.env.JWT_EXPIRATION,
    });
  } catch (error) {
    logger.error(`Error in login: ${error.message}`);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

const refreshToken = (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken == null) {
    return res.status(401).json({ message: "No refresh token provided" });
  }

  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const accessToken = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRATION }
    );
    res.status(200).json({
      accessToken,
      expiresIn: process.env.JWT_EXPIRATION,
    });
  });
};

const logout = (req, res) => {
  // Invalidate the refresh token here (e.g., by removing it from a database)
  res.status(200).json({ message: "Logout successful" });
};

const checkEmailAvailability = async (req, res) => {
  try {
    const { email } = req.query;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return sendResponse(res, 400, { message: "Email already exists" });
    }
    sendResponse(res, 200, { message: "Email is available" });
  } catch (error) {
    logger.error(`Error in checkEmailAvailability: ${error.message}`);
    sendResponse(res, 500, { message: "Internal Server Error" });
  }
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  checkEmailAvailability,
};
