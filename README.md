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

# Index
- [Json Web Token (JWT)][jwt]: JWT is a compact, URL-safe means of representing claims to be transferred between two parties. It consists of three parts: header, payload, and signature.
    - Header: Contains metadata about the token
        - Typically specifies the token type (JWT) and the hashing algorithm used (e.g., HMAC SHA256 or RSA)
        - Example: `{"alg": "HS256", "typ": "JWT"}`
    - Payload: Contains claims (statements about the user and additional metadata)
        - Can include standard claims like "sub" (subject), "iat" (issued at time), "exp" (expiration time)
        - Can also include custom claims specific to your application
        - Example: `{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}`
    - Signature: Ensures the token hasn't been altered
        - Created by combining the encoded header, encoded payload, a secret, and the algorithm specified in the header
        - Used to verify that the sender of the JWT is who it says it is and to ensure the message wasn't changed along the way
    The final structure looks like this:
    `header.payload.signature`
- Refresh Token[refresh-token]:
    - Refresh token is a random string, in this case 32 characters.
    - The refresh token is a long-lived token that is used to get a new access token when the current access token expires or the frontend is refreshed.
    - The refresh token is stored in the frontend's http-only cookies and is used to get a new access token when the current access token expires or the frontend is refreshed.