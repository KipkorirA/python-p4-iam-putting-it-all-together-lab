from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from bcrypt import hashpw, gensalt, checkpw
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    bio = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    recipes = db.relationship('Recipe', backref='user', lazy=True)
    
    @hybrid_property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = hashpw(password.encode('utf-8'), gensalt())
    
    def check_password(self, password):
        return checkpw(password.encode('utf-8'), self.password_hash)
    
    @validates ('username')
    def validate_username(self, key, value):
        if not value or value.strip() == '':
            raise ValueError('Username cannot be empty')
        return value

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    @validates('instructions')
    def validate_instructions(self, key, value):
        if len(value) < 50:
            raise ValueError('Instructions must be at least 50 characters long')
        return value   
