# app.py

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from datetime import datetime

# Initialize Flask and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complaints.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class BaseModel(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Role(BaseModel):
    __tablename__ = 'roles'
    name = db.Column(db.String(50), unique=True)
    users = db.relationship('User', backref='role')


class User(UserMixin, BaseModel):
    __tablename__ = 'users'
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))


class Category(BaseModel):
    __tablename__ = 'categories'
    name = db.Column(db.String(50), unique=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    assigned_role = db.relationship('Role')


class Complaint(BaseModel):
    __tablename__ = 'complaints'
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='New')
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    category = db.relationship('Category')
    user = db.relationship('User')
    assigned_role = db.relationship('Role', foreign_keys=[role_id])

# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class FlaskApp:
    def __init__(self, app, db):
        self.app = app
        self.db = db
        
        # Initialize services and controllers
        self.auth_service = AuthService()
        self.complaint_service = ComplaintService()
        self.auth_controller = AuthController(self.auth_service)
        self.complaint_controller = ComplaintController(self.complaint_service)
        
        self.setup_routes()

    def run(self, debug=True):
        self.app.run(debug=debug)

    def setup_routes(self):
        self.app.add_url_rule('/', view_func=self.index, methods=['GET'])
        self.app.add_url_rule('/login', view_func=self.login, methods=['GET', 'POST'])
        self.app.add_url_rule('/register', view_func=self.register, methods=['GET', 'POST'])
        self.app.add_url_rule('/logout', view_func=self.logout)
        self.app.add_url_rule('/file_complaint', view_func=self.file_complaint, methods=['GET', 'POST'])
        self.app.add_url_rule('/assign_complaint/<int:complaint_id>', view_func=self.assign_complaint, methods=['GET', 'POST'])
        self.app.add_url_rule('/update_complaint/<int:complaint_id>', 
                         'update_complaint', 
                         self.update_complaint, 
                         methods=['GET', 'POST'])

    @login_required
    def index(self):
        return self.complaint_controller.index()

    def login(self):
        return self.auth_controller.login()

    def register(self):
        return self.auth_controller.register()

    @login_required
    def logout(self):
        return self.auth_controller.logout()

    @login_required
    def file_complaint(self):
        return self.complaint_controller.file_complaint()

    @login_required
    def assign_complaint(self, complaint_id):
        return self.complaint_controller.assign_complaint(complaint_id)

    @login_required
    def update_complaint(self, complaint_id):
        complaint = Complaint.query.get_or_404(complaint_id)
    
        # Allow both Secretary and assigned role to update
        if current_user.role.name != 'Secretary' and complaint.role_id != current_user.role.id:
            flash('Access denied')
            return redirect(url_for('index'))
    
        if request.method == 'POST':
            status = request.form.get('status')
            progress = request.form.get('progress')
            complaint.status = status
            if progress:
                complaint.progress = progress
            db.session.commit()
            flash('Complaint updated successfully')
            return redirect(url_for('index'))
        
        return render_template('update_complaint.html', complaint=complaint)

class AuthController:
    def __init__(self, auth_service):
        self.auth_service = auth_service

    def login(self):
        if request.method == 'POST':
            return self.auth_service.login(
                request.form.get('username'),
                request.form.get('password')
            )
        return render_template('login.html')

    def register(self):
        if request.method == 'POST':
            return self.auth_service.register(
                request.form.get('username'),
                request.form.get('password')
            )
        return render_template('register.html')

    def logout(self):
        return self.auth_service.logout()

class ComplaintController:
    def __init__(self, complaint_service):
        self.complaint_service = complaint_service

    def index(self):
        complaints = self.complaint_service.get_complaints_for_user(current_user)
        return render_template('index.html', complaints=complaints)

    def file_complaint(self):
        if request.method == 'POST':
            return self.complaint_service.create_complaint(
                request.form.get('description'),
                request.form.get('category'),
                current_user.id
            )
        categories = Category.query.all()
        return render_template('file_complaint.html', categories=categories)

    def assign_complaint(self, complaint_id):
        if current_user.role.name != 'Secretary':
            flash('Access denied')
            return redirect(url_for('index'))
        
        if request.method == 'POST':
            return self.complaint_service.assign_complaint(
                complaint_id,
                request.form.get('assigned_role')
            )
        
        complaint = Complaint.query.get_or_404(complaint_id)
        roles = Role.query.filter(Role.name != 'Secretary').all()
        return render_template('assign_complaint.html', complaint=complaint, roles=roles)

class AuthService:
    def login(self, username: str, password: str):
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash('Logged in successfully')
            return redirect(url_for('index'))
        flash('Invalid username or password')
        return redirect(url_for('login'))

    def register(self, username: str, password: str):
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        user_role = Role.query.filter_by(name='User').first()
        user = User(username=username, password=password, role=user_role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful')
        return redirect(url_for('login'))

    def logout(self):
        logout_user()
        flash('Logged out successfully')
        return redirect(url_for('login'))

class ComplaintService:
    def get_complaints_for_user(self, user):
        if user.role.name == 'Secretary':
            return Complaint.query.all()
        elif user.role.name == 'User':
            return Complaint.query.filter_by(user_id=user.id).all()
        return Complaint.query.filter_by(role_id=user.role.id).all()

    def create_complaint(self, description: str, category_id: int, user_id: int):
        complaint = Complaint(
            description=description,
            category_id=category_id,
            user_id=user_id
        )
        db.session.add(complaint)
        db.session.commit()
        flash('Complaint filed successfully')
        return redirect(url_for('index'))

    def assign_complaint(self, complaint_id: int, role_id: int):
        complaint = Complaint.query.get_or_404(complaint_id)
        role = Role.query.get(role_id)
        if role:
            complaint.role_id = role.id
            complaint.status = f'Assigned to {role.name}'
            db.session.commit()
            flash('Complaint assigned successfully')
        else:
            flash('Invalid role selected')
        return redirect(url_for('index'))

# Create application instance
flask_app = FlaskApp(app, db)

if __name__ == '__main__':
    flask_app.run(debug=True)