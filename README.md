# Advanced Flask Authentication Project

This project is a backend authentication and authorization system developed using Python and the Flask framework.
The main goal of the project is to demonstrate how secure user login systems work in real-world web applications.

The application is designed as an API-based backend system, not a visual website.
Users interact with the system by sending HTTP requests instead of using a graphical interface.

The project starts by initializing a Flask application.
Flask is a lightweight web framework for Python that allows developers to build web applications and APIs easily.
It handles incoming HTTP requests, routes them to the correct functions, and returns responses to the client.

To store user data, the project uses SQLite, which is a simple and lightweight database.
SQLite is suitable for small and medium-sized projects and does not require a separate database server.
When the application starts, the database file is created automatically if it does not exist.

The database contains a users table with the following fields:
- username
- password (stored as a hashed value for security)
- role (user or admin)

Security is one of the most important parts of this project.
User passwords are never stored as plain text.
Instead, they are hashed using Werkzeug’s password hashing functions.
When a user logs in, the entered password is hashed again and compared with the stored hash.
This ensures that even if the database is compromised, real passwords cannot be recovered.

The project supports two authentication methods: Basic Authentication and JWT Authentication.

Basic Authentication is a simple authentication method that uses a username and password.
It is mainly included in this project for learning and comparison purposes.
A protected route is provided where only users authenticated with Basic Auth can access the resource.

JWT (JSON Web Token) Authentication is the main authentication method used in the project.
When a user successfully logs in, the system generates an access token and a refresh token.
These tokens are digitally signed and contain user identity information such as username and role.
The access token is required to access protected endpoints.

JWT authentication is stateless, meaning the server does not store session information.
All required information is stored inside the token itself.
This makes the system scalable and suitable for modern web applications.

User registration is implemented to allow new users to create an account.
During registration, the system checks whether the username already exists.
If the username is unique, the user is added to the database with a default role of "user" unless another role is specified.

After registration, users can log in using their credentials.
If the credentials are correct, the system returns JWT tokens.
If the credentials are incorrect, the system returns an error message.

Authorization is implemented using role-based access control.
Some routes are available to all authenticated users, while others are restricted to admin users only.
The admin-only route checks the role value stored inside the JWT token.
If the user does not have the admin role, access is denied with a proper error message.

The project also includes middleware for logging.
Every incoming HTTP request is logged with its method and path.
Logs are saved in a file called app.log.
This feature is useful for debugging, monitoring, and security auditing.

Error handling is implemented to improve user experience and system reliability.
The application returns clear JSON error messages for different authentication issues such as:
- Missing token
- Invalid token
- Expired token
- Unauthorized access

These error responses help users understand why a request failed.

To run the project, Python 3 must be installed on the system.
After cloning the project from GitHub, the required libraries should be installed using pip.
Once the application is started, Flask runs a local development server on port 5000.

Since this is a backend API project, opening the root URL in a browser does not display a web page.
The system is tested using tools like Postman or curl by sending HTTP requests to the available endpoints.

In conclusion, this project demonstrates the core concepts of backend development using Flask.
It covers authentication, authorization, database usage, password security, logging, and error handling.
The project is designed for educational purposes and reflects real-world backend application architecture.
