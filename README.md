# Authentication API

This project is a Node.js application that provides a robust authentication system using Express, MongoDB, JWT, bcrypt, and Swagger for API documentation.

## Table of Contents

- [Authentication API](#authentication-api)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running the Application](#running-the-application)
  - [Running Tests](#running-tests)
  - [API Documentation](#api-documentation)
  - [Project Structure](#project-structure)
  - [License](#license)
  - [Contact](#contact)

## Features

- User registration and login
- JWT-based authentication
- Token refresh functionality
- Password hashing with bcrypt
- Protected routes
- Email availability check
- Comprehensive API documentation with Swagger
- Error handling and logging

## Requirements

- Node.js (>=14.x)
- MongoDB (>=4.x)

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/hisham-mhammed-afifi/auth-app-nodejs.git
   cd auth-app-nodejs
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Create an environment configuration file**

   Create a `.env` file in the root directory with the following content:

   ```env
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/auth-app
   JWT_SECRET=your_secret_key
   JWT_EXPIRATION=15m
   JWT_REFRESH_EXPIRATION=7d
   EMAIL_USER=your_email@example.com
   EMAIL_PASS=your_email_password
   FRONTEND_URL=your_host_client_url
   ```

## Configuration

Make sure to replace `your_secret_key` with a strong secret key. Adjust other configurations as needed.

## Running the Application

1. **Start the MongoDB server**

   Ensure MongoDB is running on your local machine or adjust the `MONGODB_URI` in the `.env` file to point to your MongoDB server.

2. **Start the application**

   ```bash
   npm start
   ```

   The server will start on the port specified in the `.env` file (default is 3000).

## Running Tests

1. **Ensure MongoDB is running**

   Ensure MongoDB is running on your local machine or adjust the `MONGODB_URI` in the `.env` file to point to your MongoDB test server.

2. **Run the tests**

   ```bash
   npm test
   ```

   This command will execute the unit tests using Jest.

## API Documentation

Access the Swagger UI for API documentation at:

- Local: [http://localhost:3000/api-docs](http://localhost:3000/api-docs)
- Production: [https://auth-app-nodejs-fuco.onrender.com/api-docs](https://auth-app-nodejs-fuco.onrender.com/api-docs)

## Project Structure

```
/auth-app
  /config
    db.js           # Database connection setup
    logger.js       # Logger configuration
  /controllers
    auth.controller.js # Authentication controller
  /errors
    custom.errors.js # Cutom resuable errors
  /middlewares
    auth.middleware.js # Middleware for token authentication
    errorHandler.middleware.js # Middleware for handling errors
  /models
    user.js         # User model
  /routes
    auth.routes.js  # Authentication routes
  .env              # Environment variables
  app.js            # Main application file
  package.json      # Project metadata and dependencies
  .gitignore        # Git ignore file
  README.md         # Project documentation
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any questions or suggestions, please contact [hish.abdelshafouk@gmail.com].
