# Savvi Auth Service

This is a Golang-based authentication microservice. This project uses docker containers for the database, cache and the main application.

Features:
- User Management
- Auth Token Management
- Google OAuth Authentication

Only admin users can use all user management endpoints.
Non admin users can only use the auth related endpoints and their own user related endpoints. AKA the user id requested must match the user id stored in the jwt payload.

## API Endpoints
- GET `/health`: Health check endpoint

### User Management
- POST `/register`: Create a new user
- GET `/user/{id}`: Get user by id
- PUT `/user/{id}`: Update user by id
- DELETE `/user/{id}`: Delete user by id
- GET `/users`: Get all users

### Auth Token Management
- POST `/token`: Get access token (login with username and password)
- POST `/token/validate`: Validate access token
- POST `/token/refresh`: Refresh access token
- POST `/token/revoke`: Revoke access token (logout)

### Google OAuth
- GET `/login/google`: Initiate Google OAuth login
- GET `/auth/google/callback`: Google OAuth callback URL

# Database
PostgresSQL is used to store the users.

# Cache
Redis is used to store the refresh tokens and users.

## Deployment
This application is designed to be deployed using Docker. The `docker-compose.yml` file is used to define and run the Docker containers for the application.

To build and run the application, use the following command:
```bash
docker-compose up --build
```

# Notes
## Authentication Methodology
This applications uses [JWT][jwt] for authentication. The JWT is signed using the SECRET_KEY environment variable.
This jwt will be used by microservices to authenticate users and by a frontend to get the [refresh token][refresh-token]. The refresh token will be used to get a new access token when the current access token expires or the frontend is refreshed.

# TODO SPEEDRUN
[x] Create all handlers noted above for the API, returning dummy values for now
[] Implement user service management
[] Implement each handler already specified
[] add password reset handler
[] add the protected routes middleware
[] add logging middleware

# TODO
[] refactor to hex architecture
[] add unit and integration tests



