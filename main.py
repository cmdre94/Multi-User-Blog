import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'blah'


def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

# Lesson says we don't have to use this initialize function but it is important
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# USER ==============================================================


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# BLOG ======================================================


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    author = db.StringProperty()
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    total_likes = db.IntegerProperty()
    like = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    comment_author = db.StringProperty()
    comment_content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    c_post_id = db.IntegerProperty()

    def render(self):
        self._render_text = self.comment_content.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class BlogFront(Handler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        comments = Comment.all().order('-created')
        self.render('front.html', posts=posts, comments=comments)


class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = Comment.all().order('-created')

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments)


class NewPost(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name
        total_likes = 0
        like = self.request.get('like')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     author=author, total_likes=total_likes, like=like)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error, author=author, total_likes=total_likes)


class EditPost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("editpost.html", post=post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

# This error is thrown in the post method after the submit button is clicked
# I like it better in the get method so the user is unable to get to the edit
# post page.
        if self.user.name != post.author:
            error = "Only post authors can edit their own posts"
            self.render('error.html', error=error)

        elif subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))

        else:
            post.error = "subject and content, please!"
            self.render("editpost.html", post=post)


class DeletePost(Handler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

# The only way to attempt to delete another user's post is by entering the url
# in the address bar. If this happens I want to throw an error in their face.
        if self.user.name != post.author:
            error = "Only post authors can delete their own posts"
            return self.render('error.html', error=error)

        if not post:
            self.error(404)
            return

        else:
            self.render('deletepost.html', post=post)

    def post(self, post_id):
        ok = self.request.get('ok')

        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)

# This error is here per requierments, but It should never get this far because
# the same error is thrown in the get method.
            if self.user.name != post.author:
                error = "Only post authors can delete their own posts"
                return self.render('error.html', error=error)

            elif ok:
                post.delete()
                self.redirect('/blog/?')

            else:
                key = db.Key.from_path("Post", int(post_id), parent=blog_key())
                post = db.get(key)
                self.redirect('/blog/?')


class NewComment(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("newcomment.html", post=post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not self.user:
            self.redirect('/blog')

        comment_content = self.request.get('comment_content')
        comment_author = self.user.name
        c_post_id = int(post_id)

# The Post author can't comment on their own posts. Don't want to go so deep
# as to be able to comment on your own comment, or even better comment on a
# commenters comment about your comment.  That could get crazy.
        if self.user.name == post.author:
                error = "Post authors can't comment on their own posts"
                return self.render('error.html', error=error)

        elif comment_content:
            c = Comment(comment_content=comment_content,
                        comment_author=comment_author,
                        c_post_id=c_post_id)
            c.put()
            # self.redirect('/blog', post = post)#%s' % str(post.key().id()))
            return self.redirect('/blog/%s' % str(post.key().id()))

        else:
            post.comment_error = "content, please!"
            self.render("newcomment.html", post=post)


class EditComment(Handler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if not self.user:
            error = "Please log in or sign up"
            self.render('error.html', error=error)

        elif self.user:
            self.render('editcomment.html', comment=comment)

        if not comment:
            self.error(404)
            return

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if not self.user:
            return self.redirect('/blog')

        comment_content = self.request.get('comment_content')

# Only the comment author can edit their own comments.
        if self.user.name != comment.comment_author:
            error = "Only comment author can edit."
            self.render('error.html', error=error)

        elif comment_content:
            comment.comment_content = comment_content
            comment.put()
            self.redirect('/blog/?')

        else:
            comment.error = "content, please!"
            self.render("editcomment.html", comment=comment)


class DeleteComment(Handler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if not self.user:
            error = "Please log in or sign up"
            self.render('error.html', error=error)

        elif self.user:
            self.render('deletecomment.html', comment=comment)

        if not comment:
            self.error(404)
            return

    def post(self, comment_id):
        ok = self.request.get('ok')
        if self.user:
            key = db.Key.from_path("Comment", int(comment_id))
            comment = db.get(key)

# Only the comment author can delete their own comments
            if self.user.name != comment.comment_author:
                error = "Only comment author can delete."
                return self.render('error.html', error=error)

            elif ok:
                comment.delete()
                self.redirect('/blog/?')


class CommentHistory(Handler):
    def get(self):
        comments = Comment.all().order('-created')
        self.render('history.html', comments=comments)


class NewLike(Handler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        like_button = self.request.get('like')

        if like_button:
            if post.like == self.user.name:
                error = "You already liked this post"
                return self.render('error.html', error=error)
# made sure user can't like their own post even though it's not
# possible with the given UI.
            elif self.user.name == post.author:
                error = "Post author cannot like their own post."
                return self.render('error.html', error=error)
            else:
                post.like = self.user.name
                post.total_likes += 1
                post.put()
                self.redirect('/blog/?')

            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)


class Unlike(Handler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        unlike_button = self.request.get('unlike')

        if unlike_button:
            if post.like != self.user.name:
                error = "You must like before you can unlike"
                self.render('error.html', error=error)
            else:
                post.like = "None"
                post.total_likes -= 1
                post.put()
                self.redirect('/blog/?')

            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

# SIGNUP =================================================================


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Signup page


class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Unit3Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit2/signup', Unit2Signup),
                               ('/welcome', Welcome),
                               ('/unit2/welcome', Welcome),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/newcomment/([0-9]+)', NewComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/like/([0-9]+)', NewLike),
                               ('/unlike/([0-9]+)', Unlike),
                               ('/blog/history', CommentHistory),
                               ], debug=True)
