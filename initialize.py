# initialize.py
from app import app, db, Role, User, Category
from typing import Dict, List

class DatabaseInitializer:
    def __init__(self):
        self.app = app
        self.db = db
        self.role_objects: Dict[str, Role] = {}

    def reset_database(self):
        with self.app.app_context():
            self.db.drop_all()
            self.db.create_all()

    def create_roles(self) -> None:
        roles: List[str] = [
            'Secretary',
            'Treasurer',
            'Maintenance_Head',
            'Electrician',
            'Plumber',
            'Security_Head',
            'Security_Guard',
            'Housekeeping_Supervisor',
            'Gardener',
            'Gym_Instructor',
            'Pool_Maintenance',
            'Accountant',
            'User'
        ]

        for role_name in roles:
            role = Role(name=role_name)
            self.db.session.add(role)
            self.db.session.flush()
            self.role_objects[role_name] = role

    def create_default_users(self) -> None:
        default_users = [
            {'username': 'secretary', 'password': 'pass', 'role': 'Secretary'},
            {'username': 'treasurer', 'password': 'pass', 'role': 'Treasurer'},
            {'username': 'maintenance', 'password': 'pass', 'role': 'Maintenance_Head'},
            {'username': 'electrician', 'password': 'pass', 'role': 'Electrician'},
            {'username': 'plumber', 'password': 'pass', 'role': 'Plumber'},
            {'username': 'security', 'password': 'pass', 'role': 'Security_Head'},
            {'username': 'user1', 'password': 'pass', 'role': 'User'}
        ]

        for user_data in default_users:
            role = self.role_objects.get(user_data['role'])
            if role:
                user = User(
                    username=user_data['username'],
                    password=user_data['password'],
                    role=role
                )
                self.db.session.add(user)

    def create_categories(self) -> None:
        categories = [
            {'name': 'Electrical Issues', 'role': 'Electrician'},
            {'name': 'Plumbing Issues', 'role': 'Plumber'},
            {'name': 'Security Issues', 'role': 'Security_Head'},
            {'name': 'Maintenance', 'role': 'Maintenance_Head'},
            {'name': 'Gardening', 'role': 'Gardener'},
            {'name': 'Housekeeping', 'role': 'Housekeeping_Supervisor'},
            {'name': 'Gym Equipment', 'role': 'Gym_Instructor'},
            {'name': 'Swimming Pool', 'role': 'Pool_Maintenance'},
            {'name': 'Accounts/Billing', 'role': 'Accountant'}
        ]

        for cat_data in categories:
            role = self.role_objects.get(cat_data['role'])
            if role:
                category = Category(
                    name=cat_data['name'],
                    role_id=role.id
                )
                self.db.session.add(category)

    def initialize_database(self):
        try:
            with self.app.app_context():
                self.reset_database()
                self.create_roles()
                self.create_default_users()
                self.create_categories()
                self.db.session.commit()
                print("Database initialized successfully.")
        except Exception as e:
            print(f"Error initializing database: {e}")
            self.db.session.rollback()

if __name__ == '__main__':
    initializer = DatabaseInitializer()
    initializer.initialize_database()