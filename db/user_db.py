# user_db.py
from pymongo import MongoClient

class UserDB:
    def __init__(self):
        # MongoDB Atlas connection string
        self.client = MongoClient('mongodb+srv://omermishania:MONGO_PASSWORD@cluster0.z3hbjqh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
        self.db = self.client['middlemanpayments']
        self.users = self.db['users']

    def insert_user(self, user_data):
        """ Insert a user into the database """
        result = self.users.insert_one(user_data)
        return str(result.inserted_id)

    def find_user_by_email(self, email):
        """ Find a user by their email """
        return self.users.find_one({"email": email})

    def find_user_by_id(self, id):
        """ Find a user by their ID """
        return self.users.find_one({"_id": id})

    def list_users(self):
        """ List all users """
        return list(self.users.find())

    def login_user(self):
        """ List all users """
        return list(self.users.find())
