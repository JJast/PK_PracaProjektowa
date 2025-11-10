# WebAuthn Demo Application

This is a demo application showcasing WebAuthn (Web Authentication) integration with Flask backend and React frontend. The application demonstrates passwordless authentication and multi-factor authentication using WebAuthn standards.

## Features

- User registration with password + optional WebAuthn
- User login with password
- Multi-factor authentication with WebAuthn
- Secure session management
- Modern React frontend with animations
- RESTful Flask API backend
- SQLite database for user and credential storage

## Prerequisites

- Python 3.8 or higher
- Node.js 16 or higher
- npm or yarn
- A WebAuthn-compatible browser (most modern browsers)
- A WebAuthn authenticator (built-in platform authenticator or security key)

## Installation & Setup

### Backend (Flask)

1. Create and activate a Python virtual environment:

```bash
# From the App directory
python -m venv .venv
.\.venv\Scripts\activate  # On Windows
source .venv/bin/activate  # On Unix/macOS
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

### Frontend (React)

1. Install Node.js dependencies:

```bash
# From the front-react directory
npm install
```

## Running the Application

1. Start the Flask backend:

```bash
# From the App directory, with virtual environment activated
python app.py
```

The backend will run on http://localhost:5000

2. Start the React development server:

```bash
# From the front-react directory
npm run dev
```

The frontend will run on http://localhost:5173

## Testing the Application

1. Open http://localhost:5173 in your browser
2. Create a new account:
   - Click "Sign Up"
   - Enter email and password
   - If prompted, follow WebAuthn registration process
3. Log in:
   - Enter your credentials
   - If WebAuthn is enabled, use your authenticator when prompted
4. You'll be redirected to the dashboard upon successful authentication

## Security Features

- CSRF protection via secure sessions
- Password hashing using Werkzeug
- WebAuthn credential storage with sign count verification
- Cross-origin resource sharing (CORS) protection
- Secure cookie handling

## Development

The project structure:

```
App/
├── app.py              # Flask backend
├── requirements.txt    # Python dependencies
├── front-react/        # React frontend
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── styles/     # CSS styles
│   │   └── utils/      # Utilities and constants
│   └── package.json    # Node.js dependencies
└── static/            # Static files
```

## Common Issues

1. WebAuthn not working:

   - Ensure you're using HTTPS or localhost
   - Check if your browser supports WebAuthn
   - Verify you have an available authenticator

2. Session issues:
   - Clear browser cookies
   - Ensure CORS settings match your development environment

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License.
