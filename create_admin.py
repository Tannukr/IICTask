from app import app, db, User
from werkzeug.security import generate_password_hash

def create_admin():
    with app.app_context():
        # Check if admin user exists
        admin = User.query.filter_by(email='admin@gmail.com').first()
        
        if admin:
            # Update existing admin user
            admin.username = 'admin'
            admin.password = generate_password_hash('admin123', method='pbkdf2:sha256')
            admin.is_admin = True
            print("Admin user updated successfully!")
        else:
            # Create new admin user
            admin = User(
                username='admin',
                email='admin@gmail.com',
                password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin)
            print("Admin user created successfully!")
        
        db.session.commit()
        print("Username: admin")
        print("Password: admin123")
        print("Email: admin@gmail.com")

if __name__ == '__main__':
    create_admin() 