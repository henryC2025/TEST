from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId
import json
import requests
import datetime
import jwt
import uuid
from functools import wraps
#from authlib.jose import JsonWebKey, JsonWebToken


app = Flask(__name__)


client = MongoClient("mongodb://127.0.0.1:27017")
db = client['gamesDB']  
collection = db['video_games']  
users = db['staff']
blacklist = db['blacklist']

domain = 'dev-lj7ac84a7apx1w1e.us.auth0.com'
clientID = 'V1vpytxkkPCX6I2Aebhi0jGowtyH8rf8'
clientSecret = 'n2Gdz0jvJjCNekH9jUup8329_uHjnl4FhrqyAO3AAf9VESK0mLJ0rY0k7QBu8Bzv'

app.config['SECRET_KEY'] = 'mysecret'

def admin_acquired(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers['x-access-token']
        data = jwt.decode(token, app.config['SECRET_KEY'])
        if data['admin']:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify({'message' : 'Admin access required'}), 401)
    return admin_required_wrapper

def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        #token = request.args.get('token')
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except: 
            return jsonify({'message' : 'Token is invalid'}), 401
        
        bl_token = blacklist.find_one({'token' : token})
        if bl_token is not None:
            return make_response(jsonify({'message' : 'Token has been cancelled'}), 401)


        return func(*args, **kwargs)
    
    return jwt_required_wrapper

@app.route('/')
def hello_world():
    return 'Hello, World!'

# get all games
@app.route('/api/v1.0/games', methods=['GET'])
def get_all_games():

    page_num, page_size = 1, 10
    if request.args.get('pn'): 
        page_num = int(request.args.get('pn'))
    if request.args.get('ps'):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))

    video_games_list = []

    for game in db.video_games.find().skip(page_start).limit(page_size):
        game['_id'] = str(game['_id'])
        video_games_list.append(game)

    return make_response(jsonify(video_games_list), 200)

# get a game by id
@app.route('/api/v1.0/games/<string:id>', methods=['GET'])
def get_game_by_id(id):
    video_game = db.video_games.find_one({"_id": ObjectId(id)})

    if video_game:
        video_game['_id'] = str(video_game['_id'])
        for comment in video_game.get('comments', []):
            comment['_comment_id'] = str(comment['_comment_id'])

        return make_response(jsonify(video_game), 200)
    else:
        return make_response(jsonify({"message": "Game not found"}), 404)

# search games by name
@app.route('/api/v1.0/games/search', methods=['GET'])
def search_games():
    query = request.args.get('query', '')

    regex_pattern = f'.*{query}.*'
    query_filter = {'name': {'$regex': regex_pattern, '$options': 'i'}}

    matching_games = db.video_games.find(query_filter)

    matching_games_list = []
    for game in matching_games:
        game['_id'] = str(game['_id']) 
        matching_games_list.append(game)

    return make_response(jsonify(matching_games_list), 200)

# /api/v1.0/businesses/<string:id>
@app.route('/api/v1.0/games/<string:game_id>/comments', methods=['POST'])
def add_comment(game_id):
    comment_id = ObjectId()
    timestamp = datetime.datetime.utcnow()

    username = request.form["username"]
    comment_text = request.form["comment"]

    if username and comment_text:
        new_comment = {
            "username": username,
            "_comment_id": comment_id,
            "comment_text": comment_text,
            "datetime": timestamp,
        }

        collection.update_one(
            {"_id": ObjectId(game_id)},
            {"$push": {"comments": new_comment}}
        )

        return make_response(jsonify({'message': 'Comment added successfully'}), 201)
    else:
        return make_response(jsonify({'error_message': 'Comment could not be added'}), 404)
    
# delete a comment using the game id and comment id
@app.route('/api/v1.0/games/<string:game_id>/comments/<string:comment_id>', methods=['DELETE'])
def delete_comment(game_id, comment_id):
    result = collection.update_one(
        {"_id": ObjectId(game_id)},
        {"$pull": {"comments": {"_comment_id": ObjectId(comment_id)}}}
    )

    if result.modified_count > 0:
        return make_response(jsonify({'message': 'Comment deleted successfully'}), 200)
    else:
        return make_response(jsonify({'error_message': 'Comment not found or deletion failed'}), 404)

# edit a comment using the game id and comment id
@app.route('/api/v1.0/games/<string:game_id>/comments/<string:comment_id>', methods=['PUT'])
def edit_comment(game_id, comment_id):
    
    timestamp = datetime.datetime.utcnow()
    username = request.form["username"]
    comment_text = request.form["comment"]

    new_comment = {

            "username": username,
            "_comment_id": comment_id,
            "comment_text": comment_text,
            "datetime": timestamp,
        }


    return

# FAVOURITE GAMES {GAME_ID}

# ADD FAVOURITE GAMES

# DELETE FAVOURITE GAMES

# EDIT FAVOURITE GAMES

# ADD FILTERS FOR VIEW ALL GAMES

if __name__ == '__main__':
    app.run(debug=True)


# BLACKLIST COLLECTION 


# USERS COLLECTION

# user_list = [
#           { 
#             "name" : "Henry Chan",
#             "username" : "henry2025",  
#             "password" : b"apple123",
#             "email" : "herny2025@msn.com",
#             "admin" : True
#           }
#        ]

# for new_staff_user in user_list:
#       new_staff_user["password"] = bcrypt.hashpw(new_staff_user["password"], bcrypt.gensalt())
#       user_list.insert_one(new_staff_user)
