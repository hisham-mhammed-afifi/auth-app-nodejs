require("dotenv").config();
const express = require("express");
const connectDB = require("./config/db");
const logger = require("./config/logger");
const authRoutes = require("./routes/auth.routes");
const { authenticateToken } = require("./middlewares/auth.middleware");
const setupSwagger = require("./swagger");

const app = express();

connectDB();

app.use(express.json());

// Setup Swagger
setupSwagger(app);

// Routes
app.use("/api/auth", authRoutes);

// Protected route example
app.get("/api/protected", authenticateToken, (req, res) => {
  res.send("This is a protected route");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
