const errorHandler = (err, req, res, next) => {
  // Define custom error responses based on error type or properties
  if (err.name === "ValidationError") {
    return res.status(400).json({ message: err.message });
  }

  if (err.name === "UnauthorizedError") {
    return res.status(401).json({ message: err.message });
  }

  if (err.name === "ForbiddenError") {
    return res.status(403).json({ message: err.message });
  }

  if (err.name === "NotFoundError") {
    return res.status(404).json({ message: err.message });
  }

  // Handle JWT errors
  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({ message: err.message });
  }

  if (err.name === "TokenExpiredError") {
    return res.status(401).json({ message: err.message });
  }

  // Handle MongoDB duplicate key error
  if (err.code && err.code === 11000) {
    return res.status(409).json({ message: "Duplicate key error" });
  }

  // General server error
  res.status(500).json({ message: "Internal Server Error" });
};

module.exports = errorHandler;
