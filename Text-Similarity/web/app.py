from flask import Flask, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy


app = Flask(__name__)
api = Api(app)

client  = MongoClient("mongodb://db:27017")
db = client.similarityDB
users = db["users"]

def userExist(username):
    if users.count_documents({"username":username}) == 0:
        return False
    else:
        return True

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if userExist(username):
            retJson = {
                "status" : 301,
                "msg" : "Invalid username"
            }

            return retJson

        hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())

        users.insert_one({
            "username" : username,
            "password" : hashed_pw,
            "tokens" : 6
            })
        
        retJson = {
            "status" : 200,
            "msg" : "You've successfully signed up to the Api"
        }

        return retJson

def verifyPw(username, password):
    if not userExist(username):
        return False
    
    hashed_pw = users.find({
        "username" : username
    })[0]["password"]

    if bcrypt.hashpw(password.encode("utf8"),hashed_pw) == hashed_pw:
        return True
    else:
        return False

def countTokens(username):
    tokens = users.find({
        "username" : username
    })[0]["tokens"]
    return tokens

class Detect(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if not userExist(username):
            retJson = {
                "status" : 301,
                "msg" : "Invalid username"
            }
            return retJson

        correct_pw  = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "status" : 302,
                "msg" : "Invalid password"
            }
            return retJson
        
        num_tokens = countTokens(username)

        if num_tokens <= 0:
            retJson = {
                "status" :303,
                "msg" : "You're out of tokens, please refill"
            }
            return retJson

        #Caculate the edit distance
        nlp = spacy.load('en_core_web_sm')

        text1 = nlp(text1)
        text2 = nlp(text2)


        #Ratio is a number between 0 and 1
        ratio = text1.similarity(text2)

        retJson = {
            "status" : 200,
            "ratio" : ratio,
            "msg" : "Similarity score caculated successfully."
        }

        current_tokens = countTokens(username)

        users.update_one({
            "username": username
        },{
            "$set" : {
                "tokens" : current_tokens - 1
            }
        })

        return retJson
class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        refill_amount = postedData["refill"]


        if not userExist(username):
            retJson = {
                "status": 301,
                "msg": "Invalid Username"
            }
            return retJson
        
        correct_pw = "123xyz"

        if not password == correct_pw:
            retJson = {
                "status" : 304,
                "msg" : "Invalid admin Password"
            }
            return retJson

        current_tokens = countTokens(username)
        users.update_one({
            "username" : username,
        },{
            "$set" : {"tokens" :  refill_amount + current_tokens}
        })

        retJson = {
            "status" : 200,
            "msg" : "Refilled Successfully"
        }
        return retJson


api.add_resource(Register, "/register")
api.add_resource(Detect,"/detect")
api.add_resource(Refill,"/refill")

if __name__ == "__main__":
    app.run(host = '0.0.0.0')
