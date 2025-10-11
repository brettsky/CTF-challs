Challenge Desc

The fundamental characteristic of a hypertext is that its pages contain hyperlinks to other pages, in a network of mutual references called the Web.

In this challenge, a network of pages can be reached via the URL http://web-16.challs.olicyber.it/. The flag is contained within the title ( h1) of one of these pages. The goal is to automatically traverse the network of pages until reaching the one containing the flag.

It is recommended to use the find_alllibrary method BeautifulSoupto isolate the tags <a>and extract the destination address from the attribute href, and to keep a set of the visited pages so as not to analyze them more than once, to avoid creating unnecessary load on the server being analyzed and to avoid being trapped in an infinite loop in case two or more pages were to link to each other.

In-depth: A software that explores a network of pages by following all the hyperlinks is called a spider, and it is a fundamental component of modern search engines.


We have to create a spider that will crawl the webpages and get the flag.

We did this challenge within kali linux and developed the script in Vscode- copying it into nano 

first run wget to get a list of links:

wget --no-clobber --no-parent --spider -r http://web-16.challs.olicyber.it/ 2>&1 | grep '^--' | awk '{print $3}' | tee urls2.txt


We then got a list of urls and wrote lvl16-Brett.py to parse through each webpage using get requests and regex to find the flag. 


'''
import requests
import re


def iter_urls(file_path: str = 'urls2.txt'):
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith('#'):
                continue
            yield url


for url in iter_urls():
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        flags = re.findall(r'flag\{[^}]+\}', response.text)
        print(flags)
    except requests.RequestException:
        print([])
'''