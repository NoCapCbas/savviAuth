# Savvi Auth Service

This is a FastAPI-based authentication service with support for both local authentication and Google OAuth.

## TODO:
[x] create localauth
[] create github workflow package
[] create prod deployment container
[] add Google OAuth support

## Google OAuth Integration Steps

To integrate Google OAuth into this service, follow these steps:

1. Add Google OAuth dependencies:
   - Install required packages: `pip install authlib starlette`
   - Import new dependencies in `main.py`:
     ```python
     from authlib.integrations.starlette_client import OAuth
     from starlette.config import Config
     ```

2. Set up Google OAuth configuration:
   - Add the following code near the top of `main.py`:
     ```python
     config = Config('.env')
     oauth = OAuth(config)

     GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
     GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

     oauth.register(
         name='google',
         server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
         client_kwargs={'scope': 'openid email profile'}
     )
     ```

3. Add Google login and callback routes:
   - Import `RedirectResponse` and add new routes in `main.py`:
     ```python
     from starlette.responses import RedirectResponse

     @app.get('/login/google')
     async def login_google(request):
         redirect_uri = request.url_for('auth_callback')
         return await oauth.google.authorize_redirect(request, redirect_uri)

     @app.get('/auth/callback')
     async def auth_callback(request):
         token = await oauth.google.authorize_access_token(request)
         user = await oauth.google.parse_id_token(request, token)
         # Implement user creation/login logic here
         return RedirectResponse(url='/success')
     ```

4. Modify the User model:
   - Update the User model in `main.py` to include Google-specific fields:
     ```python
     class User(Base):
         __tablename__ = "users"

         id = Column(Integer, primary_key=True, index=True)
         email = Column(String, unique=True, index=True)
         first_name = Column(String)
         last_name = Column(String)
         hashed_password = Column(String, nullable=True)
         google_id = Column(String, unique=True, nullable=True)
         disabled = Column(Boolean, default=False)
     ```

5. Update authentication logic:
   - Modify the `get_current_user` function to handle Google-authenticated users.

6. Update login endpoint:
   - Modify the `/token` endpoint to support both password and Google authentication.

7. Update registration process:
   - Modify the `/register` endpoint to handle Google-authenticated users.

8. Environment variables:
   - Add `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` to your `.env` file or environment variables.

## Next Steps

- Implement user creation/login logic in the Google OAuth callback
- Update the frontend to include Google login buttons
- Test the integration thoroughly
- Ensure compliance with Google's OAuth usage policies
- Implement secure handling of user data

## Running the Application

1. Set up your environment variables in a `.env` file or your deployment environment.
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python main.py`

The server will start on `http://0.0.0.0:8000`.

## API Endpoints

- `/register`: Register a new user
- `/token`: Get access token (login)
- `/users/me`: Get current user information
- `/health`: Health check endpoint
- `/login/google`: Initiate Google OAuth login
- `/auth/callback`: Google OAuth callback URL

## Security Notes

- Ensure all sensitive information (database credentials, secret keys, etc.) are stored securely and not in the codebase.
- Use HTTPS in production.
- Regularly update dependencies to patch security vulnerabilities.
