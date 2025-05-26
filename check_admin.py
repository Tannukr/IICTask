from app import app, db, User
from werkzeug.security import generate_password_hash

def check_and_fix_admin():
    with app.app_context():
        # Get all users
        users = User.query.all()
        print("\nAll users in database:")
        for user in users:
            print(f"Username: {user.username}, Email: {user.email}, Is Admin: {user.is_admin}")
        
        # Get admin user
        admin = User.query.filter_by(is_admin=True).first()
        if admin:
            print(f"\nAdmin user found: {admin.username}")
            # Reset admin password to a known value
            admin.password = generate_password_hash('admin123', method='pbkdf2:sha256')
            db.session.commit()
            print("Admin password has been reset to: admin123")
        else:
            print("\nNo admin user found!")

if __name__ == '__main__':
    check_and_fix_admin() 