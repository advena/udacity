import os
import webapp2
import jinja2
import logging
import re
from datetime import datetime

from handlers import *
from db import *
from cache import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                              autoescape = True)



class Handler(webapp2.RequestHandler):

    ''' Handlers to simple manage the site creation '''


    def write(self,*a, **kw):
        self.response.out.write(*a,**kw)

    def render_str(self,template,**params):
        temp=jinja_env.get_template(template)
        return temp.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def cookie_handler(self, cookie_val):

        ''' Creates unique and hashed cookie for the new user '''

        visits = 0
        if cookie_val:
            cookie_val = check_secure_val(cookie_val)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1
        #hash the cookie_val
        new_cookie = make_secure_val(str(visits))
        #set the new cookie value to the header
        self.response.headers.add_header(str(new_cookie))

    
    def user_validate(self):

        #chceck if given user isn't already registere
        user_id = self.request.cookies.get('user_id')
        #if user_id isn't None if is set to default value
        if user_id:
            if check_secure_val(user_id):
                user_id = user_id.split('|')[0]
                username = get_user_by_id(int(user_id))
                return username
        
    def content_get(self, page_id):
        
        return page_cache(page_id)

    def version_get(self, page_id): 
    
        version = self.request.get('v')
        if version:
            content = self.content_get(page_id + '?v=' + version)
        else:
            content = self.content_get(page_id)
        return content


    def url_get(self, page_id):

        version = self.request.get('v')
        if version:
            url = page_id + '?v=' + version
        else:
            url = page_id
        
        return url



class MainPage(Handler):
    
    ''' Handler for the main and any wiki page '''


    def render_main(self, login = '', 
                          content = '', 
                          edit = '',
                          logout = '',
                          username = ''):

        self.render('main.html', login = login, 
                                 content = content, 
                                 edit = edit, 
                                 logout = logout,
                                 username = username)


    def user_rendering(self, username, content):
        ''' Renders the page for logged in user'''
        
        logout = '(logout)'
        edit = 'edit'
        self.render_main(content = content,
                         username = username,
                         logout = logout,
                         edit = edit)

    def anonim_render(self, content):
        ''' Renders the page for annonim user'''
        login = 'login'
        self.render_main(login = login, content = content)
    
    def get_page_id(self, page_id, identifier=''):

        ''' Retruns pure page_id removes the identifiers if whether it is at
            the begging or the end of the page url '''

        #split the page_id to get all elements
        p = page_id.split('/')
        p.remove(identifier[1:])
        logging.error('/'.join(p))
        return '/'.join(p)
        

class WikiPage(MainPage):

    def render_history(self, history = '',
                            username = '',
                            login = '',
                            logout = '',
                            edit = ''):

        self.render('history.html', history = history,
                                    username = username,
                                    login = login,
                                    logout = logout,
                                    edit = edit)


    def get(self, page_id):

        #check if page_id isn't history
        if '/_history' in page_id:
            self.redirect('/_history' + self.get_page_id(page_id, '/_history'))

        
        #check if page_id isn't edition 
        elif '/_edit' in page_id:
            logging.error('redtirection: ' + page_id)
            logging.error('/_edit' +  self.get_page_id(page_id, '/_edit'))
            self.redirect('/_edit' +  self.url_get(self.get_page_id(page_id, '/_edit')))

        else:
        
            username = self.user_validate()
            #get the version of the page and then the content
            content = self.version_get(page_id)
            #check if user is logged in
            if username:
                logging.error(page_id)
                #check if page exsts
                if content:
                    self.user_rendering(username, content)
                else:
                    #create new page with empty content and redirect user to edit page
                    new_page = Pages(url = page_id, content = '', version = 0, page_id = page_id)
                    new_page.put()
                    self.redirect('/_edit' + page_id)

            else:
                #now for annonymous user check if content exists
                if content:
                    self.anonim_render(content)
                else:
                    #redirect user to main page
                    logging.error('redirection error')
                    self.redirect('/')
        

class Signup(Handler):

    ''' Signup handler adds new user to the database
        hahses the password and creates cookie '''


    def render_form(self, username = '',
                          password = '',
                          verify = '',
                          email = '',
                          user_error = '',
                          pw_error = '',
                          verify_error = '',
                          unique_error = '',
                          email_error = ''):

        self.render('signup.html', username = username,
                                   password = password,
                                   verify = verify,
                                   email = email,
                                   user_error = user_error,
                                   pw_error = pw_error, 
                                   verify_error = verify_error, 
                                   unique_error = unique_error, 
                                   email_error = email_error) 
    def get(self): 
        self.render_form()

    def post(self):

        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        user_error = pw_error = verify_error = unique_error = email_error = ''
        
        #validate username, password and email, check if username is unique
        users = user_cache('users')

        if (valid_user(username) and 
           valid_password(password) and 
           valid_email(email) and
           password == verify and not 
           (username in users)):

            #create new entry for that user
            new_user = Users(username = username,
                             password = make_pw_hash(username, password),
                             email = email)

            user_key = new_user.put()
            
            #set new cookie for that user using his id
            user_id = user_key.id()
            new_cookie_id = make_secure_val(str(user_id))
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % new_cookie_id)

            #add that user name to cache
            add_username(username)
            self.redirect('/')

        else:
            #check what fields aren't valid
            if username in users:
                unique_error = 'User with that name already exists'
            if not valid_user(username):
                user_error = 'Name is not valid!'
            if not valid_password(password):
                pw_error = 'Passoword is not valid!'
            if not valid_email(email):
                email_error = 'Email is not valid!'
            if password != verify and pw_error == '':
                verify_error = 'Passwords did\'t match!'


        self.render_form(username,
                         password,
                         email,
                         user_error,
                         pw_error, 
                         verify_error, 
                         unique_error,
                         email_error)
           


class Login(Handler):
    
    ''' Login handler validates the user '''

    def get(self):
        self.render('login.html', error = '')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        #chcek if user exists
        users = user_cache('users')
        if username in users:
            #get the given user password to chceck whether is valid
            user = get_user_by_name(username)
            user_h = user.password
            if valid_pw(username, password, user_h):
                #set the cookie for that user
                user_id = user.key().id()
                new_cookie_val = make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie', 'user_id=%s' % new_cookie_val)
                self.redirect('/')
            else:
                self.render('login.html', error = 'Invalid login')

        else:
            self.render('login.html', error = 'Invalid login')

class Logout(Handler):
    
    ''' Logout handler removes the cookie from header and sets the user to annonymous '''


    def get(self):
        empty_cookie = ''
        self.response.headers.add_header('Set-Cookie', 'user_id=%s' %empty_cookie)
        self.redirect('/')


class EditPage(Handler):

    ''' Handler for editing existing and new created pages
        checks if user is logged in and adds new entry to database '''


    def render_edit(self, content = '', 
                          page_id = '',
                          username = ''):
        self.render('edit.html', content = content, 
                                 page_id = page_id,
                                 username = username)


    def get(self, page_id):
        #check if user is already logged in
        username = self.user_validate()
        if username:
            #user has the premision to edit page
            #get the content of that page
            content = self.version_get(page_id)
            self.render_edit(content = content, page_id = page_id, username = username)
        else:
            #user is not logged in redirect to login page
            self.redirect('/login')

    def post(self, page_id):
        
        #check if user is already logged in
        username = self.user_validate()
        if username:
            #get the content of page
            content = self.request.get('content')
            #get the page
            logging.error(page_id)
            updated_page = get_page_by_id(page_id)
            #get the version of page
            version = updated_page.version

            #update the content and versions
            updated_page.content = content
            updated_page.version = version + 1
            updated_page.put()
            
            #create new page with history url
            self.add_history_entry(page_id, content, version + 1)
            #lastly update the memcache for that page
            update_page_cache(page_id, content)
            self.redirect(page_id)
        else:
            self.redirect(page_id)

    
    def add_history_entry(self, page_id, content, version):
        
        url = page_id + '?v=' + str(version) #create url
        new_entry = Pages(page_id = page_id, url = url, content = content, version = version)
        new_entry.put()


class HistoryPage(Handler):

    ''' History handler presents all previous edition of parent page
        also provides an edition of older versions and sets it as the new one '''


    def render_history(self, history = '',
                            username = '',
                            login = '',
                            logout = '',
                            edit = ''):

        self.render('history.html', history = history,
                                    username = username,
                                    login = login,
                                    logout = logout,
                                    edit = edit)

    def get(self, page_id):

        #get all versions of page
        pages = get_page_history(self.get_page_id(page_id))
            
        #check if user is already logged in
        username = self.user_validate()
        if username:
            logout = '(logout)'
            edit = 'edit'
            self.render_history(history = pages, username = username, 
                                             logout = logout, 
                                             edit = edit)
        else:
            login = 'login'
            self.render_history(history = pages, login = login)



        



# regex pattern to get the page_id
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

# application handler 

app = webapp2.WSGIApplication([
                                ('/signup', Signup),
                                ('/login', Login),
                                ('/logout', Logout),
                                ('/_edit' + PAGE_RE, EditPage),
                                (PAGE_RE, WikiPage),
                                ('/_history' + PAGE_RE, HistoryPage)],
                                debug = True)
