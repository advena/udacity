from google.appengine.ext import db
import json


class Users(db.Model):

    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)


class Pages(db.Model):

    url = db.StringProperty(required = True)
    page_id = db.StringProperty(required = True)
    content = db.TextProperty()
    version = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)



def get_page_by_id(page_id):

    return db.GqlQuery('SELECT * FROM Pages WHERE url=:1 LIMIT 1',  page_id).get()

def get_user_by_name(username):
        
    return db.GqlQuery('SELECT * FROM Users WHERE username=:1 LIMIT 1',  username).get()

def get_page_history(page_id):

    return db.GqlQuery('SELECT * FROM Pages WHERE page_id=:1', page_id)

def get_user_by_id(user_id):

    return Users.get_by_id(user_id).username

    

