import re
import hashlib
import crypt
import random
import string
import hmac



###############################VALIDATION FORMS#####################################################
def valid_user(username):

    user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    if user_re.match(username):
        return True
    return False

def valid_password(password):

    pswd_re = re.compile(r"^.{3,20}$") 
    if pswd_re.match(password):
        return True
    return False


def valid_email(email):

    email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    if email_re.match(email) or email == '':
        return True
    return False


####################################VALIDATION PASSWORDS AND COOKIES##################################
SECRET = 'serafdgavsdhrt5hsdf'

def hash_str(string):
    '''Hashes the given string with md5 algorithm'''
    
    return hmac.new(SECRET, string).hexdigest()


def make_secure_val(string):
    ''' Returns the string that contains a string and the hash value for
        that string'''

    return '%s|%s' % (string, hash_str(string))


def check_secure_val(string):
    ''' Checks if given string matches the hash value'''

    s_value = string.split('|')[0]
    if make_secure_val(s_value) == string:
        return s_value

def make_salt():
    ''' Randomly creates salt '''
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    ''' Hashes the password with given salt, if salt isn't provided calls make_salt()'''
    if not salt:
        salt = make_salt()
    h = crypt.crypt(name + pw + salt, salt)
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    ''' Validates both password and name with given hash h'''
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)
