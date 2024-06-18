require("dotenv").config();
const request = require("supertest");
const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");
const User = require("../models/User");
const authRoutes = require("../routes/auth.routes");
const errorHandler = require("../middlewares/errorHandler.middleware");

const app = express();

app.use(helmet());
app.use(express.json());
// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
  message: "Too many requests from this IP, please try again after 15 minutes",
});
app.use("/api/auth", limiter);
app.use("/api/auth", authRoutes);

app.use(errorHandler);

// Mock the logger to avoid logging during tests
jest.mock("../config/logger", () => ({
  error: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));

// Connect to a test database
beforeAll(async () => {
  await mongoose.connect("mongodb://localhost:27017/auth_test");
});

// Clear the test database after each test
afterEach(async () => {
  await User.deleteMany({});
});

// Disconnect from the test database
afterAll(async () => {
  await mongoose.connection.close();
});

describe("Auth Controller", () => {
  // Register a new user -----------------------------------
  describe("POST /api/auth/register", () => {
    it("should register a new user", async () => {
      const res = await request(app).post("/api/auth/register").send({
        username: "testuser",
        email: "testuser@example.com",
        password: "password123",
      });

      expect(res.statusCode).toEqual(201);
      expect(res.body).toHaveProperty(
        "message",
        "User registered successfully"
      );
    });

    it("should return an error if the email already exists", async () => {
      const newUser = new User({
        username: "testuser",
        email: "testuser@example.com",
        password: "password123",
      });

      await newUser.save();

      const res = await request(app).post("/api/auth/register").send({
        username: "testuser2",
        email: "testuser@example.com",
        password: "password123",
      });

      expect(res.statusCode).toEqual(400);
      expect(res.body).toHaveProperty("message", "Email already exists");
    });

    it("should return an error for invalid input", async () => {
      const res = await request(app)
        .post("/api/auth/register")
        .send({ username: "te", email: "invalidemail", password: "123" });

      expect(res.statusCode).toEqual(400);
      expect(res.body).toHaveProperty("message");
    });
  });

  // Login -------------------------------------------------
  describe("POST /api/auth/login", () => {
    it("should login a user with valid credentials", async () => {
      const newUser = new User({
        username: "testuser",
        email: "testuser5@example.com",
        password: await bcrypt.hash("password123", 10),
      });

      await newUser.save();

      const res = await request(app)
        .post("/api/auth/login")
        .send({ email: "testuser5@example.com", password: "password123" });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty("accessToken");
      expect(res.body).toHaveProperty("refreshToken");
    });

    it("should return an error for invalid credentials", async () => {
      await User.create({
        username: "testuser",
        email: "testuser@example.com",
        password: await bcrypt.hash("password123", 10),
      });

      const res = await request(app)
        .post("/api/auth/login")
        .send({ email: "testuser@example.com", password: "wrongpassword" });

      expect(res.statusCode).toEqual(401);
      expect(res.body).toHaveProperty("message", "Invalid credentials");
    });

    it("should return an error for a non-existent user", async () => {
      const res = await request(app).post("/api/auth/login").send({
        email: "nonexistentuser@example.com",
        password: "password123",
      });

      expect(res.statusCode).toEqual(401);
      expect(res.body).toHaveProperty("message", "Invalid credentials");
    });
  });

  // check email -------------------------------------------
  describe("GET /api/auth/check-email", () => {
    it("should return available if email does not exist", async () => {
      const res = await request(app)
        .get("/api/auth/check-email")
        .query({ email: "available@example.com" });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty("message", "Email available");
    });

    it("should return an error if email already exists", async () => {
      await User.create({
        username: "testuser",
        email: "testuser@example.com",
        password: "password123",
      });

      const res = await request(app)
        .get("/api/auth/check-email")
        .query({ email: "testuser@example.com" });

      expect(res.statusCode).toEqual(400);
      expect(res.body).toHaveProperty("message", "Email already exists");
    });
  });

  // refresh token ------------------------------------------
  describe("POST /api/auth/refresh-token", () => {
    it("should refresh the access token", async () => {
      const user = new User({
        username: "testuser",
        email: "testuser@example.com",
        password: await bcrypt.hash("password123", 10),
      });

      await user.save();

      const refreshToken = jwt.sign(
        { username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRATION }
      );

      const res = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty("accessToken");
    });

    it("should return an error if no refresh token is provided", async () => {
      const res = await request(app).post("/api/auth/refresh-token").send({});

      expect(res.statusCode).toEqual(401);
      expect(res.body).toHaveProperty("message", "No refresh token provided");
    });

    it("should return an error for an invalid refresh token", async () => {
      const res = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: "invalidToken" });

      expect(res.statusCode).toEqual(403);
      expect(res.body).toHaveProperty("message", "Invalid refresh token");
    });
  });

  // logout ------------------------------------------------
  describe("POST /api/auth/logout", () => {
    it("should log out the user successfully", async () => {
      const res = await request(app).post("/api/auth/logout").send();

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty("message", "Logout successful");
    });
  });

  // request password ----------------------------------------
  describe("POST /api/auth/request-password-reset", () => {
    it("should send a password reset link", async () => {
      const user = new User({
        username: "testuser",
        email: "testuserr@example.com",
        password: await bcrypt.hash("password123", 10),
      });

      await user.save();

      const res = await request(app)
        .post("/api/auth/request-password-reset")
        .send({ email: "testuserr@example.com" });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty("message", "Password reset link sent");
    });

    it("should return an error if the user is not found", async () => {
      const res = await request(app)
        .post("/api/auth/request-password-reset")
        .send({ email: "nonexistentuser@example.com" });

      expect(res.statusCode).toEqual(404);
      expect(res.body).toHaveProperty("message", "User not found");
    });
  });

  // reset password ----------------------------------------
  describe("POST /api/auth/reset-password", () => {
    it("should reset the password successfully", async () => {
      const user = new User({
        username: "testuser",
        email: "testuser@example.com",
        password: await bcrypt.hash("password123", 10),
      });

      const resetToken = crypto.randomBytes(32).toString("hex");
      const hashedToken = await bcrypt.hash(resetToken, 10);

      user.resetPasswordToken = hashedToken;
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      await user.save();

      const res = await request(app).post("/api/auth/reset-password").send({
        token: resetToken,
        email: "testuser@example.com",
        newPassword: "newpassword123",
      });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty("message", "Password reset successful");
    });

    it("should return an error for an invalid or expired token", async () => {
      const user = new User({
        username: "testuser",
        email: "testuser@example.com",
        password: await bcrypt.hash("password123", 10),
      });

      await user.save();

      const res = await request(app).post("/api/auth/reset-password").send({
        token: "invalidToken",
        email: "testuser@example.com",
        newPassword: "newpassword123",
      });

      expect(res.statusCode).toEqual(400);
      expect(res.body).toHaveProperty("message", "Invalid or expired token");
    });

    it("should return an error if the user is not found", async () => {
      const res = await request(app).post("/api/auth/reset-password").send({
        token: "someToken",
        email: "nonexistentuser@example.com",
        newPassword: "newpassword123",
      });

      expect(res.statusCode).toEqual(404);
      expect(res.body).toHaveProperty("message", "User not found");
    });
  });

  // update profile -------------------------------------------
  describe("PUT /api/auth/update-profile/:userId", () => {
    it("should update the user profile successfully", async () => {
      const user = new User({
        username: "testuser",
        email: "testuser@example.com",
        password: await bcrypt.hash("password123", 10),
      });

      await user.save();

      const res = await request(app)
        .put(`/api/auth/update-profile/${user._id}`)
        .send({
          username: "updateduser",
          email: "updateduser@example.com",
        });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty(
        "message",
        "Profile updated successfully"
      );
      expect(res.body.user).toHaveProperty("username", "updateduser");
      expect(res.body.user).toHaveProperty("email", "updateduser@example.com");
    });

    it("should return an error if the user is not found", async () => {
      const res = await request(app)
        .put("/api/auth/update-profile/60c72b2f9b1d4c1f887fa1c9")
        .send({
          username: "updateduser",
          email: "updateduser@example.com",
        });

      expect(res.statusCode).toEqual(404);
      expect(res.body).toHaveProperty("message", "User not found");
    });
  });
});
