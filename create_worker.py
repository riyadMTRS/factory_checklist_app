from database import create_user

def create_worker_user():
    username = input("Enter worker username: ")
    password = input("Enter worker password: ")
    full_name = input("Enter worker full name: ")
    email = input("Enter worker email (optional, press Enter to skip): ")
    
    success, message = create_user(username, password, 'worker', full_name, email)
    print(message)

if __name__ == "__main__":
    create_worker_user() 