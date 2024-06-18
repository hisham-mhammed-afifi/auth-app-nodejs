const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const logger = require("../config/logger");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

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
      return res.status(409).json({ message: "Email already exists" });
    }
    res.status(200).json({ message: "Email available" });
  } catch (error) {
    logger.error(`Error in checkEmailAvailability: ${error.message}`);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

const requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = await bcrypt.hash(resetToken, 10);

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}&email=${email}`;

    // Send email (Configure your email service)
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      to: email,
      from: process.env.EMAIL_USER,
      subject: "Password Reset",
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
             Please click on the following link, or paste this into your browser to complete the process:\n\n
             ${resetLink}\n\n
             If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "Password reset link sent" });
  } catch (error) {
    logger.error(`Error in requestPasswordReset: ${error.message}`);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (
      !user.resetPasswordToken ||
      !user.resetPasswordExpires ||
      Date.now() > user.resetPasswordExpires
    ) {
      return res
        .status(400)
        .json({ message: "Password reset token is invalid or has expired" });
    }

    const isTokenValid = await bcrypt.compare(token, user.resetPasswordToken);
    if (!isTokenValid) {
      return res.status(400).json({ message: "Invalid token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    logger.error(`Error in resetPassword: ${error.message}`);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  checkEmailAvailability,
  requestPasswordReset,
  resetPassword,
};
