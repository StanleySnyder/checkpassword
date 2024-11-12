import hashlib
import re

def check_password_complexity(password):
    if len(password) < 8:
        return False, "Пароль должен быть не менее 8 символов"
    
    if not re.search(r'[a-z]', password):
        return False, "Пароль должен содержать хотя бы одну строчную букву"
    
    if not re.search(r'[A-Z]', password):
        return False, "Пароль должен содержать хотя бы одну прописную букву"
    
    if not re.search(r'[0-9]', password):
        return False, "Пароль должен содержать хотя бы одну цифру"
    
    return True, "Пароль подходит"

def calculate_sha256(password):
    sha256 = hashlib.sha256()
    
    sha256.update(password.encode('utf-8'))
    
    return sha256.hexdigest()

if __name__ == "__main__":
    password = input("Введите пароль: ")

    is_valid, message = check_password_complexity(password)
    
    if is_valid:
        password_hash = calculate_sha256(password)
        print(f"Пароль прошел проверку. Хэш пароля: {password_hash}")
    else:
        print(f"Ошибка: {message}")
