class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
  }
}

class UnauthorizedError extends Error {
  constructor(message) {
    super(message);
    this.name = "UnauthorizedError";
  }
}

class ForbiddenError extends Error {
  constructor(message) {
    super(message);
    this.name = "ForbiddenError";
  }
}

class NotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = "NotFoundError";
  }
}

class JsonWebTokenError extends Error {
  constructor(message) {
    super(message);
    this.name = "JsonWebTokenError";
  }
}

class TokenExpiredError extends Error {
  constructor(message) {
    super(message);
    this.name = "TokenExpiredError";
  }
}

module.exports = {
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  JsonWebTokenError,
  TokenExpiredError,
};
