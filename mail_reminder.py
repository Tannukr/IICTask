# from flask_mail import Mail, Message
# from datetime import datetime, timedelta
# from threading import Thread
# from app import app
# from flask import redirect,render_template,url_for,flash,session


# # Email Configuration
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
# app.config['MAIL_PORT'] = 587  
# app.config['MAIL_USE_TLS'] = True  
# app.config['MAIL_USERNAME'] = 'krishn20114@gmail.com'  
# app.config['MAIL_PASSWORD'] = '"wtmt zalv sjqq hyxh'  
# app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'  

# mail = Mail(app)

# # Background function to send emails
# def send_async_email(app, msg):
#     with app.app_context():
#         mail.send(msg)

# def send_reminder_email(user_email, task):
#     msg = Message("Task Reminder ⏰", recipients=[user_email])  # Use user email
#     msg.body = f"Reminder: You have a pending task - '{task.content}'. Please complete it before {task.deadline.strftime('%Y-%m-%d')}!"
#     Thread(target=send_async_email, args=(app, msg)).start()

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

SENDER_EMAIL = os.getenv('EMAIL_USER', 'krishn20114@gmail.com')
SENDER_PASSWORD = os.getenv('EMAIL_PASSWORD', 'wtmtzalvsjqqhyxh')

def create_task_list_html(tasks):
    task_list = ""
    for task in tasks:
        due_date = task.deadline.strftime('%Y-%m-%d %H:%M') if task.deadline else "No deadline"
        status = "⚠️ Overdue" if task.deadline and task.deadline < datetime.utcnow() else "⏰ Pending"
        priority_color = {
            'High': '#dc3545',
            'Medium': '#ffc107',
            'Low': '#28a745'
        }.get(task.priority, '#6c757d')

        task_list += f"""
        <div style="margin-bottom: 15px; padding: 10px; border-left: 4px solid {priority_color}; background-color: #f8f9fa;">
            <h3 style="margin: 0; color: #333;">{task.content}</h3>
            <p style="margin: 5px 0; color: #666;">
                <strong>Priority:</strong> <span style="color: {priority_color}">{task.priority}</span><br>
                <strong>Due:</strong> {due_date}<br>
                <strong>Status:</strong> {status}
            </p>
        </div>
        """
    return task_list

def send_reminder_email(recipient_email, subject, tasks):
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    msg['Subject'] = subject

    # Create the email body
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #1e3c72; text-align: center;">TaskMaster Reminder</h2>
                <p>Hello,</p>
                <p>{subject}</p>
                <div style="background-color: #f4f4f4; padding: 20px; margin: 20px 0; border-radius: 5px;">
                    <h3 style="color: #1e3c72; margin-top: 0;">Your Pending Tasks:</h3>
                    <ul style="list-style-type: none; padding: 0;">
                        {''.join(f'<li style="margin-bottom: 10px; padding: 10px; background: white; border-radius: 5px;">• {task.content}</li>' for task in tasks)}
                    </ul>
                </div>
                <p>Please log in to your TaskMaster account to view and manage your tasks.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="text-align: center; color: #666; font-size: 12px;">
                    This is an automated message, please do not reply.
                </p>
            </div>
        </body>
    </html>
    """

    msg.attach(MIMEText(body, 'html'))

    try:
        print(f"Attempting to send email to {recipient_email} from {SENDER_EMAIL}")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.set_debuglevel(1)  # Enable debug output
        server.starttls()
        print("TLS connection established")
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        print("Login successful")
        server.send_message(msg)
        print("Message sent successfully")
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"Authentication failed: {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False
