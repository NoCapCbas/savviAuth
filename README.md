# Savvi Auth Service

This is a FastAPI-based authentication service with support for both local authentication and Google OAuth.

## TODO:
[x] create localauth
[x] add Google OAuth support
[] create github workflow package
[] create prod docker-compose file
[] create prod dockerfile
[] deploy to prod

## API Endpoints

- `/register`: Register a new user
- `/token`: Get access token (login)
- `/users/me`: Get current user information
- `/health`: Health check endpoint
- `/login/google`: Initiate Google OAuth login
- `/auth/google/callback`: Google OAuth callback URL
