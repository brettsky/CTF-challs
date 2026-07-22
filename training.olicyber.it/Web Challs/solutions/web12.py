import requests 
from bs4 import BeautifulSoup

url = "http://web-12.challs.olicyber.it/"

response = requests.get(url)

html_content = response.text



soup = BeautifulSoup(html_content, 'html.parser')


element = soup.find_all('p')

print(element[1])