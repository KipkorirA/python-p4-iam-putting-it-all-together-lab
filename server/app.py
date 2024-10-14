#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api, bcrypt
from models import User, Recipe


### SIGNUP ###
class Signup(Resource):
    def post(self):
        data = request.get_json()

        try:
            # Extract required fields
            username = data['username']
            password = data['password']
            bio = data.get('bio', '')
            image_url = data.get('image_url', '')

            # Create new user
            new_user = User(username=username, password=password, bio=bio, image_url=image_url)
            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id  # Log the user in
            return jsonify(new_user.to_dict()), 201

        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already taken'}, 409

        except Exception as e:
            return {'error': str(e)}, 400


### CHECK SESSION ###
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.get(user_id)
            return jsonify(user.to_dict()), 200
        else:
            return {'error': 'No active session'}, 401


### LOGIN ###
class Login(Resource):
    def post(self):
        data = request.get_json()

        # Extract login details
        username = data['username']
        password = data['password']

        # Check if the user exists
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id  # Log the user in
            return jsonify(user.to_dict()), 200
        else:
            return {'error': 'Invalid username or password'}, 401


### LOGOUT ###
class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)  # Log out by removing session data
        return {'message': 'Logged out successfully'}, 204


### RECIPE INDEX (Fetch all or add a new recipe) ###
class RecipeIndex(Resource):
    def get(self):
        recipes = Recipe.query.all()
        return jsonify([recipe.to_dict() for recipe in recipes]), 200

    def post(self):
        user_id = session.get('user_id')

        if not user_id:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json()

        try:
            # Extract recipe details
            title = data['title']
            instructions = data['instructions']
            minutes_to_complete = data.get('minutes_to_complete', 0)

            if len(instructions) < 50:
                return {'error': 'Instructions must be at least 50 characters long'}, 400

            # Create a new recipe
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id  # Associate the recipe with the logged-in user
            )
            db.session.add(new_recipe)
            db.session.commit()

            return jsonify(new_recipe.to_dict()), 201

        except Exception as e:
            return {'error': str(e)}, 400


# Add resources to the API
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
