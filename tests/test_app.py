import unittest
from flask import current_app
from project import create_app, db
from project.models import User
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from bs4 import BeautifulSoup
import re


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "SQLALCHEMY_DATABASE_URI": 'sqlite://'} )
        self.app.config['WTF_CSRF_ENABLED'] = False  # no CSRF during tests
        self.appctx = self.app.app_context()
        self.appctx.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.drop_all()
        self.appctx.pop()
        self.app = None
        self.appctx = None
        self.client = None

    def test_app(self):
        assert self.app is not None
        assert current_app == self.app

    def test_homepage_redirect(self):
        response = self.client.get('/', follow_redirects = True)
        assert response.status_code == 200

    def test_registration_form(self):
        response = self.client.get('/signup')
        assert response.status_code == 200

    def test_no_access_to_profile(self):
        response = self.client.get('/profile', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.location

    def test_register_user(self):
        response = self.client.post('/signup', data = {
            'email' : 'user@test.com',
            'name' : 'test user',
            'password' : 'test123'
        }, follow_redirects = True)
        assert response.status_code == 200
        # should redirect to the login page
        assert response.request.path == '/login'

        # verify that user can now login
        response = self.client.post('/login', data = {
            'email' : 'user@test.com',
            'password' : 'test123'
        }, follow_redirects = True)
        assert response.status_code == 200
        html = response.get_data(as_text = True)
        assert 'test user' in html

    def test_hashed_passwords(self):
        response = self.client.post('/signup', data = {
            'email' : 'user@test.com',
            'name' : 'test user',
            'password' : 'test123'
        }, follow_redirects = True)
        assert response.status_code == 200
        # should redirect to the login page
        assert response.request.path == '/login'

        user = User.query.filter_by(email='user@test.com').first()
        assert user is not None
        assert check_password_hash(user.password, 'test123')

    def test_sql_injection(self):
        # Store the initial number of users in the database
        initial_user_count = db.session.query(User).count()

        # Perform the SQL injection attempt with the malicious payload
        response = self.client.post('/signup', data={
            'email': 'user@test.com"; drop table user; -- ',
            'name': 'test user',
            'password': 'test123'
        }, follow_redirects=True)

        # Assert that the response status code is 200 (successful signup)
        assert response.status_code == 200

        # Verify the user table still exists and has its contents intact
        current_user_count = db.session.query(User).count()
        assert current_user_count == initial_user_count + 1

        # Verify that the user was added with the email value as plain text
        added_user = db.session.query(User).filter_by(email='user@test.com"; drop table user; -- ').first()
        assert added_user is not None



    def test_xss_vulnerability(self):
        # Create a test user with a name containing a script tag
        xss_name = '<script>alert("XSS")</script>'
        
        # Register the test user using the malicious name
        response = self.client.post('/signup', data={
            'email': 'xss@example.com',
            'name': xss_name,
            'password': 'testpassword'
        }, follow_redirects=True)

        # Assert that the response status code is 200 (successful signup)
        assert response.status_code == 200

        # Log in the test user
        self.client.post('/login', data={
            'email': 'xss@example.com',
            'password': 'testpassword'
        })

        # Access the user's profile page
        response = self.client.get('/profile', follow_redirects=True)
        assert response.status_code == 200

        # Check if the script tag is escaped in the response
        soup = BeautifulSoup(response.data.decode('utf-8'), 'html.parser')
        displayed_name = soup.find('h1', {'class': 'title'}).text.strip()


        # Assert that the unescaped script tag is not present in the response
        assert xss_name not in displayed_name

        # Assert that the escaped version of the script tag is present in the response
        escaped_xss_name = '&lt;script&gt;alert("XSS")&lt;/script&gt;'
        assert escaped_xss_name in displayed_name

        # Access the user's profile page
        response = self.client.get('/profile', follow_redirects=True)
        assert response.status_code == 200

        # Check if the script tag is escaped in the response
        response_text = response.data.decode('utf-8')

        # Assert that the unescaped script tag is not present in the response
        assert xss_name not in response_text

        # Assert that the escaped script tag is present in the response
        escaped_xss_name = '&lt;script&gt;alert("XSS")&lt;/script&gt;'
        assert escaped_xss_name in response_text