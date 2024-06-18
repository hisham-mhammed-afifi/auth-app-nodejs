const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const logger = require("../config/logger");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const Joi = require("joi");

const {
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  JsonWebTokenError,
  TokenExpiredError,
} = require("../errors/custom.errors");

const registerSchema = Joi.object({
  username: Joi.string().min(3).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const register = async (req, res, next) => {
  try {
    const { error } = registerSchema.validate(req.body);
    if (error) {
      throw new ValidationError(error.details[0].message);
    }

    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ValidationError("Email already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res
      .status(201)
      .json({ message: "User registered successfully", userId: newUser._id });
  } catch (error) {
    logger.error(`Error in register: ${error.message}`, { requestId: req.id });
    next(error);
  }
};

const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_TIME = 1 * 60 * 60 * 1000; // 1 hour

const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      throw new UnauthorizedError("Invalid credentials");
    }

    if (user.lockUntil && user.lockUntil > Date.now()) {
      throw new ForbiddenError("Account temporarily locked");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
        user.lockUntil = Date.now() + LOCK_TIME;
      }
      await user.save();
      throw new UnauthorizedError("Invalid credentials");
    }

    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    const accessToken = jwt.sign(
      { email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRATION }
    );
    const refreshToken = jwt.sign(
      { email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRATION }
    );

    res.status(200).json({
      accessToken,
      refreshToken,
      expiresIn: process.env.JWT_EXPIRATION,
    });
  } catch (error) {
    logger.error(`Error in login: ${error.message}`, { requestId: req.id });
    next(error);
  }
};

const refreshToken = (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      throw new JsonWebTokenError("No refresh token provided");
    }

    jwt.verify(refreshToken, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        throw new ForbiddenError("Invalid refresh token");
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
  } catch (error) {
    logger.error(`Error in refreshToken: ${error.message}`, {
      requestId: req.id,
    });
    next(error);
  }
};

const logout = (req, res) => {
  res.status(200).json({ message: "Logout successful" });
};

const checkEmailAvailability = async (req, res, next) => {
  try {
    const { email } = req.query;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new ValidationError("Email already exists");
    }
    res.status(200).json({ message: "Email available" });
  } catch (error) {
    logger.error(`Error in checkEmailAvailability: ${error.message}`, {
      requestId: req.id,
    });
    next(error);
  }
};

const requestPasswordReset = async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      throw new NotFoundError("User not found");
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = await bcrypt.hash(resetToken, 10);

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}&email=${email}`;

    const transporter = nodemailer.createTransport({
      host: "smtp.ethereal.email",
      port: 587,
      secure: false, // Use `true` for port 465, `false` for all other ports
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
    logger.error(`Error in requestPasswordReset: ${error.message}`, {
      requestId: req.id,
    });
    next(error);
  }
};

const resetPassword = async (req, res, next) => {
  try {
    const { token, email, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      throw new NotFoundError("User not found");
    }

    if (
      !user.resetPasswordToken ||
      !user.resetPasswordExpires ||
      Date.now() > user.resetPasswordExpires
    ) {
      throw new ValidationError("Invalid or expired token");
    }

    const isTokenValid = await bcrypt.compare(token, user.resetPasswordToken);
    if (!isTokenValid) {
      throw new JsonWebTokenError("Invalid token");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    logger.error(`Error in resetPassword: ${error.message}`, {
      requestId: req.id,
    });
    next(error);
  }
};

const updateProfile = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { username, email } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username, email },
      { new: true }
    );

    if (!updatedUser) {
      throw new NotFoundError("User not found");
    }

    res
      .status(200)
      .json({ message: "Profile updated successfully", user: updatedUser });
  } catch (error) {
    logger.error(`Error in updateProfile: ${error.message}`, {
      requestId: req.id,
    });
    next(error);
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
  updateProfile,
};
