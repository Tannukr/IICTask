from app import app, db, Task
from sqlalchemy import text

def migrate():
    with app.app_context():
        # Add category column with default value
        db.session.execute(text('ALTER TABLE task ADD COLUMN category VARCHAR(50) DEFAULT "General"'))
        db.session.commit()
        print("Migration completed successfully!")

if __name__ == '__main__':
    migrate() 