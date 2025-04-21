from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from database import db, init_db
import os

app = Flask(__name__)
instance_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))
os.makedirs(instance_path, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "test.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
init_db(app)

# Avoid multiple db.create_all() calls
try:
    with app.app_context():
        # Check if tables exist before creating
        if not db.engine.dialect.has_table(db.engine, 'users'):
            db.create_all()
            print('Database initialized successfully.')
        else:
            print('Database already initialized.')
except Exception as e:
    print(f'Error initializing database: {str(e)}')

@app.route('/')
def hello():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run(debug=True, port=5001) 