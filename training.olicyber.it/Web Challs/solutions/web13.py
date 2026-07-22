import requests 
from bs4 import BeautifulSoup

url = "http://web-13.challs.olicyber.it/"

response = requests.get(url)

html_content = response.text



soup = BeautifulSoup(html_content, 'html.parser')

flag = soup.find_all('span', class_='red')

for letter in flag:
    print(letter.text, end="")