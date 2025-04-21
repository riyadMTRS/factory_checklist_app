from database import create_user

def create_admin_user():
    username = input("Enter admin username: ")
    password = input("Enter admin password: ")
    full_name = input("Enter admin full name: ")
    email = input("Enter admin email (optional, press Enter to skip): ")
    
    success, message = create_user(username, password, 'admin', full_name, email)
    print(message)

if __name__ == "__main__":
    create_admin_user() 