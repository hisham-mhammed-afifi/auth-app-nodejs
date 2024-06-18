require("dotenv").config();
const express = require("express");
const connectDB = require("./config/db");
const logger = require("./config/logger");
const authRoutes = require("./routes/auth.routes");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const errorHandler = require("./middlewares/errorHandler.middleware");
const { authenticateToken } = require("./middlewares/auth.middleware");
const setupSwagger = require("./swagger");

const app = express();

connectDB();

app.use(helmet());
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
  message: "Too many requests from this IP, please try again after 15 minutes",
});

setupSwagger(app);

app.use("/api/auth", limiter);

app.use("/api/auth", authRoutes);

// root route
app.get("/", (req, res) => {
  res.send("Welcome to the Auth App");
});

// Protected route example
app.get("/api/protected", authenticateToken, (req, res) => {
  res.send("This is a protected route");
});

app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
