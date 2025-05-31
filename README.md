# TaskMaster: Flask To-Do & Reminder App

TaskMaster is a full-featured To-Do web application built with Flask. It supports user registration with OTP verification, task management with priorities, categories, and deadlines, email reminders, and an admin dashboard for user and task oversight.

## Features

- User registration with OTP email verification
- Secure login/logout
- Add, edit, delete, and complete tasks
- Task priorities (High, Medium, Low) and categories
- Deadlines and overdue task highlighting
- Email reminders for pending tasks
- User profile management
- Admin dashboard for managing users and sending reminders
- Statistics and analytics for tasks
- Responsive, modern UI with custom CSS
---

## Getting Started

### Prerequisites
- Python 3.7+
- pip

**Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
 **Set up environment variables:**
   Create a `.env` file in the root directory with the following (replace with your credentials):
   ```env
   EMAIL_USER=your_gmail@gmail.com
   EMAIL_PASSWORD=your_app_password
   ```
   > **Note:** For Gmail, you may need to use an App Password.

 **Initialize the database:**
   ```bash
   python app.py  # The database will be created on first run
   ```

### Running the App
```bash
python app.py
```
Visit [http://localhost:5000](http://localhost:5000) in your browser.

---

## Project Structure
```
├── app.py                # Main Flask app
├── requirements.txt      # Python dependencies
├── create_admin.py       # Script to create admin user
├── fix_admin.py          # Script to fix admin user
├── check_admin.py        # Script to check admin user
├── migrate.py            # Database migration script
├── mail_reminder.py      # Email reminder logic
├── otp_utils.py          # OTP generation and email logic
├── static/
│   └── style.css         # Custom styles
├── templates/            # HTML templates
│   ├── *.html
└── instance/             # (Flask instance folder, e.g. for DB)
```

---

## Customization
- **Email:** Update sender email and password in `.env`.
- **Admin:** Change admin credentials in `create_admin.py` if needed.
- **Styling:** Edit `static/style.css` for custom look.

## Security Notes
- OTPs are stored in-memory (for demo). For production, use Redis or a persistent store.
- Use strong, unique passwords for admin and users.
- Never commit real credentials to version control.



---

## Credits
Developed by Tannu. 
