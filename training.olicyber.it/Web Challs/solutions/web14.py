import requests 
from bs4 import BeautifulSoup, Comment

url = "http://web-14.challs.olicyber.it/"

response = requests.get(url)

html_content = response.text

soup = BeautifulSoup(html_content, 'html.parser')

comments = soup.find_all(string=lambda text: isinstance(text, Comment))

print(comments)