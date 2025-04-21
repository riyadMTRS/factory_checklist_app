# Factory Checklist App

A modern web application for managing factory checklists and tasks, built with Flask and SQLAlchemy.

## Features

- User authentication and role-based access control
- Real-time task management with drag-and-drop interface
- Offline support with IndexedDB
- Mobile-responsive design
- Dark mode support
- Push notifications
- File upload capabilities
- Bulk task actions
- Advanced filtering and search
- Export functionality

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Virtual environment (recommended)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/factory_checklist_app.git
cd factory_checklist_app
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Unix or MacOS:
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
# On Windows:
set FLASK_APP=app.py
set FLASK_ENV=development
set SECRET_KEY=your-secret-key

# On Unix or MacOS:
export FLASK_APP=app.py
export FLASK_ENV=development
export SECRET_KEY=your-secret-key
```

## Usage

1. Initialize the database:
```bash
python database.py
```

2. Run the development server:
```bash
python app.py
```

3. Access the application:
- Local: http://localhost:5000
- Network: http://your-ip:5000

## Default Admin Account

- Username: admin
- Password: admin123

**Important**: Change the default admin password after first login.

## Directory Structure

```
factory_checklist_app/
├── app.py              # Main application file
├── config.py          # Configuration settings
├── database.py        # Database models and functions
├── requirements.txt   # Python dependencies
├── static/           # Static files
│   ├── css/         # Stylesheets
│   ├── js/          # JavaScript files
│   └── images/      # Images and icons
├── templates/        # HTML templates
│   ├── base.html    # Base template
│   ├── login.html   # Login page
│   └── errors/      # Error pages
├── uploads/         # User uploads
└── logs/           # Application logs
```

## Production Deployment

1. Update configuration:
- Set `FLASK_ENV=production`
- Use a strong `SECRET_KEY`
- Configure a production-ready database
- Set up HTTPS

2. Run with a production server:
```bash
waitress-serve --port=8000 app:app
```

## Security Features

- Password hashing with Werkzeug
- CSRF protection
- Session security
- Input validation
- XSS prevention
- SQL injection protection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the development team. 