# Marks APP

A Flask-based web application for tracking student marks and analyzing academic performance using AI-powered insights.

## Features

- User authentication (login/signup)
- Track marks across multiple subjects and papers
- AI-powered performance analysis using Mistral AI
- View performance trends and insights
- Secure session management

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **AI**: Mistral AI API
- **Frontend**: HTML, CSS, JavaScript

## Installation

1. Clone the repository
```bash
git clone https://github.com/Navanjana2005/Marks_App.git
cd Marks_APP
```

2. Create a virtual environment
```bash
python -m venv venv
```

3. Activate the virtual environment
   - **Windows**:
     ```bash
     venv\Scripts\activate
     ```
   - **macOS/Linux**:
     ```bash
     source venv/bin/activate
     ```

4. Install dependencies
```bash
pip install -r requirements.txt
```

5. Set up environment variables
Create a `.env` file in the root directory:
```
MISTRAL_API_KEY=your_mistral_api_key_here
```

## Usage

Run the application:
```bash
python app.py
```

The app will be available at `http://localhost:5000`

## Project Structure

```
Marks_APP/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # Project documentation
├── .gitignore            # Git ignore rules
├── templates/            # HTML templates
│   ├── index.html        # Home page
│   ├── login.html        # Login page
│   └── signup.html       # Signup page
└── instance/             # Instance folder (database)
    └── marks_tracker.db  # SQLite database
```

## API Endpoints

- `POST /api/ai/analyze` - Analyze student performance with AI

## Security Notes

- Keep your `MISTRAL_API_KEY` secret and never commit it to the repository
- Use environment variables for sensitive data
- The app uses secure session management with randomly generated secret keys

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



For issues or questions, please create an issue in the repository.
