from app import app, db, User
from werkzeug.security import generate_password_hash

def fix_admin():
    with app.app_context():
        # Delete empty user entries
        empty_users = User.query.filter_by(username='').all()
        for user in empty_users:
            db.session.delete(user)
        
        # Set up admin user
        admin = User.query.filter_by(username='admin').first()
        if admin:
            admin.is_admin = True
            admin.password = generate_password_hash('admin123', method='pbkdf2:sha256')
            print(f"Admin user '{admin.username}' has been fixed")
        else:
            # Create new admin user if it doesn't exist
            admin = User(
                username='admin',
                email='admin@gmail.com',
                password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin)
            print("New admin user has been created")
        
        db.session.commit()
        
        # Verify the changes
        print("\nCurrent users in database:")
        users = User.query.all()
        for user in users:
            print(f"Username: {user.username}, Email: {user.email}, Is Admin: {user.is_admin}")

if __name__ == '__main__':
    fix_admin() 