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
