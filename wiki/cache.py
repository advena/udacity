from db import *
from google.appengine.api import memcache
import logging


MAIN_PAGE = 'Welcome to the Wiki!'


def page_cache(page_id):

    content = memcache.get(page_id)

    if not content:
        #check if page alredy exists
        page = get_page_by_id(page_id)
        if page:
            memcache.set(page_id, page.content)
            content = page.content
        else:
            content = ''

    return content

def update_page_cache(page_id, content):

    memcache.set(page_id, content)


def user_cache(key):

    users = memcache.get(key)

    if not users:
        users = []
        users_db =list(db.GqlQuery('SELECT * FROM  Users'))
        for user in users_db:
            users.append(user.username)

        memcache.set(key, users)

    return users


def add_username(username):

    users = memcache.get('users')
    if not users:
        memcache.set('users', [username])

    else:
        users.append(username)
        memcache.set('users', users)

            
