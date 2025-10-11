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


```
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
```



Some one also provided a more robust script to do this challenge in lvl16_pro.py 


```
#!/usr/bin/env python3
"""
spider.py

CTF-focused multithreaded spider:


Usage (example):
python3 spider.py \  
  --start http://web-16.challs.olicyber.it/ \
  --workers 12 \
  --max-pages 2000 \
  --timeout 6 \
  --rate-delay 0.05 \
  --idle-timeout 4
"""

import argparse
import hashlib
import re
import threading
import time
import socket
from collections import defaultdict
from queue import Queue, Empty
from urllib.parse import (urlparse, urlunparse, parse_qsl, urlencode,
                          urljoin, urldefrag, quote, unquote)

import requests
from bs4 import BeautifulSoup

# Optional psutil
try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    psutil = None
    HAS_PSUTIL = False

DEFAULT_FLAG_REGEXES = [
    r"flag\{.*?\}",
    r"FLAG\{.*?\}",
    r"\bflag\b",
    r"f[\W_]*l[\W_]*a[\W_]*g",
]

TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term",
                   "utm_content", "fbclid", "gclid", "_ga"}

def canonicalize_url(base, raw_href, strip_tracking=True):
    if not raw_href:
        return None
    try:
        joined = urljoin(base, raw_href)
    except Exception:
        return None
    joined, _ = urldefrag(joined)
    parsed = urlparse(joined)

    scheme = (parsed.scheme or "http").lower()
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return None
    port = parsed.port
    netloc = hostname
    if port:
        default_port = 443 if scheme == "https" else 80
        if port != default_port:
            netloc = f"{hostname}:{port}"

    path = unquote(parsed.path or "")
    path = quote(path, safe="/%:@&?=+$,;")

    qs = parse_qsl(parsed.query, keep_blank_values=True)
    if strip_tracking:
        qs = [(k, v) for (k, v) in qs if k not in TRACKING_PARAMS]
    qs_sorted = sorted(qs, key=lambda kv: (kv[0], kv[1]))
    query = urlencode(qs_sorted, doseq=True)

    return urlunparse((scheme, netloc, path, "", query, ""))

def cheap_fingerprint(html_text, length=2000):
    if not html_text:
        return None
    snippet = " ".join(html_text.split())[:length].encode("utf-8", errors="ignore")
    return hashlib.sha1(snippet).hexdigest()

def resolve_host_ips(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
        return list({i[4][0] for i in infos})
    except Exception:
        return []

class Spider:
    def __init__(self, start_url, workers=8, max_pages=1000, timeout=8, rate_delay=0.0,
                 flag_patterns=None, stop_on_first=True, verify_ssl=True, headers=None,
                 cookies=None, idle_timeout=10.0, enable_fingerprint=False, fingerprint_length=2000,
                 use_psutil=False, strip_tracking=True):
        start_url = start_url.strip()
        self.start_url = canonicalize_url(start_url, start_url, strip_tracking=strip_tracking)
        if not self.start_url:
            raise ValueError("Invalid start URL.")
        p = urlparse(self.start_url)
        self.base_origin = f"{p.scheme}://{p.netloc}"
        self.base_host = p.hostname

        self.workers = workers
        self.max_pages = max_pages
        self.timeout = timeout
        self.rate_delay = rate_delay
        self.verify_ssl = verify_ssl
        self.headers = headers or {"User-Agent": "CTFSpider/4.0"}
        self.cookies = cookies or {}
        self.stop_on_first = stop_on_first
        self.idle_timeout = float(idle_timeout)
        self.enable_fingerprint = enable_fingerprint
        self.fingerprint_length = int(fingerprint_length)
        self.use_psutil = use_psutil and HAS_PSUTIL
        self.strip_tracking = strip_tracking

        patterns = flag_patterns or DEFAULT_FLAG_REGEXES
        self.flag_regexes = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]

        self.q = Queue()
        self.visited = set()
        self.visited_lock = threading.Lock()

        self.parent = {}
        self.parent_lock = threading.Lock()

        self.depth = {self.start_url: 0}
        self.depth_lock = threading.Lock()

        self.seen_fps = set()
        self.fps_lock = threading.Lock()

        self.found_flags = []
        self.found_lock = threading.Lock()

        self.pages_crawled = 0
        self.pages_lock = threading.Lock()

        self.last_enqueue_ts = time.time()
        self.last_enqueue_lock = threading.Lock()
        self.last_activity_ts = time.time()
        self.last_activity_lock = threading.Lock()

        self.session_local = threading.local()
        self.stop_event = threading.Event()

        with self.visited_lock:
            self.visited.add(self.start_url)
        self.q.put(self.start_url)

    def make_session(self):
        if not hasattr(self.session_local, "session"):
            s = requests.Session()
            s.headers.update(self.headers)
            s.cookies.update(self.cookies)
            self.session_local.session = s
        return self.session_local.session

    def same_origin(self, url):
        try:
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}" == self.base_origin
        except Exception:
            return False

    def match_flag(self, text):
        if not text:
            return None
        for rx in self.flag_regexes:
            m = rx.search(text)
            if m:
                return m.group(0)
        return None

    def enqueue(self, url, parent=None):
        normalized = canonicalize_url(parent or self.start_url, url, strip_tracking=self.strip_tracking)
        if not normalized or not self.same_origin(normalized):
            return False
        with self.visited_lock:
            if normalized in self.visited:
                return False
            self.visited.add(normalized)
        with self.parent_lock:
            if parent:
                self.parent[normalized] = parent
        with self.depth_lock:
            parent_depth = self.depth.get(parent, 0) if parent else 0
            self.depth[normalized] = parent_depth + 1
        self.q.put(normalized)
        with self.last_enqueue_lock:
            self.last_enqueue_ts = time.time()
        with self.last_activity_lock:
            self.last_activity_ts = time.time()
        return True

    def _update_activity(self):
        with self.last_activity_lock:
            self.last_activity_ts = time.time()

    def crawl_worker(self, tid):
        session = self.make_session()
        while not self.stop_event.is_set():
            try:
                url = self.q.get(timeout=1)
            except Empty:
                continue
            try:
                with self.pages_lock:
                    if self.pages_crawled >= self.max_pages:
                        self.stop_event.set()
                        self.q.task_done()
                        return
                    self.pages_crawled += 1

                try:
                    resp = session.get(url, timeout=self.timeout, verify=self.verify_ssl)
                    content_type = (resp.headers.get("content-type", "") or "")
                    text = resp.text if resp is not None else ""
                except Exception:
                    resp = None
                    content_type = ""
                    text = ""

                self._update_activity()
                if self.rate_delay:
                    time.sleep(self.rate_delay)

                candidate_text = (text or "") + "\n" + url
                mflag = self.match_flag(candidate_text)
                if mflag:
                    with self.found_lock:
                        self.found_flags.append((url, mflag))
                    self._update_activity()
                    if self.stop_on_first:
                        self.stop_event.set()
                        self.q.task_done()
                        return

                parse_children = True
                if self.enable_fingerprint:
                    fp = cheap_fingerprint(text, length=self.fingerprint_length)
                    if fp:
                        with self.fps_lock:
                            if fp in self.seen_fps:
                                parse_children = False
                            else:
                                self.seen_fps.add(fp)

                if resp is not None and "html" in content_type and parse_children:
                    soup = BeautifulSoup(text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        self.enqueue(a.get("href"), parent=url)
            finally:
                self.q.task_done()

    def reconstruct_path(self, url):
        path = []
        cur = url
        with self.parent_lock:
            while True:
                path.append(cur)
                if cur == self.start_url:
                    break
                cur = self.parent.get(cur)
                if cur is None:
                    break
        return list(reversed(path))

    def _build_children_map(self):
        children = defaultdict(list)
        with self.parent_lock:
            children[self.start_url] = children.get(self.start_url, [])
            for child, par in self.parent.items():
                children[par].append(child)
                children.setdefault(child, children.get(child, []))
        return children

    # --------- NEW: Proper tree with rails ---------
    def _render_tree(self, root, children_map, flags_map):
        """
        Render a proper ASCII tree with rails:
        root
        ├── child1
        │   ├── grand1
        │   └── grand2
        └── child2
        """
        lines = []
        seen = set()

        def lab(n):
            return f"{n}  [FLAG: {flags_map[n]}]" if n in flags_map else n

        def walk(node, prefix="", is_last=True):
            # root printed without connector
            if prefix == "":
                lines.append(lab(node))
            else:
                connector = "└── " if is_last else "├── "
                lines.append(prefix + connector + lab(node))

            seen.add(node)
            kids = sorted(children_map.get(node, []))
            for i, child in enumerate(kids):
                last = (i == len(kids) - 1)
                # next level prefix keeps a rail if current is not last
                next_prefix = prefix + ("    " if is_last else "│   ")
                if child in seen:
                    # avoid cycles: mark and continue
                    cyc_label = f"{child}  [CYCLE]"
                    connector = "└── " if last else "├── "
                    lines.append(next_prefix + connector + cyc_label)
                    continue
                walk(child, next_prefix, last)

        walk(root, "", True)
        return "\n".join(lines)

    def _print_pstree(self, children_map, flags_map, out_file=None):
        out_text = self._render_tree(self.start_url, children_map, flags_map)
        print("\n=== PSTREE ===")
        print(out_text)
        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(out_text)
        return out_text
    # -----------------------------------------------

    def _has_recent_remote_connections(self, remote_ips):
        if not self.use_psutil:
            return True
        try:
            conns = psutil.net_connections(kind='tcp')
        except Exception:
            return True
        for c in conns:
            if not c.raddr:
                continue
            raddr_ip = c.raddr.ip if hasattr(c.raddr, 'ip') else c.raddr[0]
            if raddr_ip in remote_ips:
                if c.status not in ('TIME_WAIT', 'CLOSE', 'CLOSED', 'NONE'):
                    return True
        return False

    def run(self):
        threads = []
        for i in range(self.workers):
            t = threading.Thread(target=self.crawl_worker, args=(i,), daemon=True)
            threads.append(t)
            t.start()

        remote_ips = resolve_host_ips(self.base_host) if self.use_psutil else []

        try:
            while True:
                if self.stop_event.is_set():
                    break
                qsize = self.q.qsize()
                with self.last_activity_lock:
                    last_act = self.last_activity_ts
                idle_for = time.time() - last_act

                remote_active = False
                if self.use_psutil and remote_ips:
                    remote_active = self._has_recent_remote_connections(remote_ips)

                if qsize == 0 and idle_for >= self.idle_timeout and (not self.use_psutil or not remote_active):
                    self.stop_event.set()
                    break

                time.sleep(0.5)
        except KeyboardInterrupt:
            print("[!] Interrupted by user.")
            self.stop_event.set()

        self.q.join()
        for t in threads:
            t.join(timeout=0.5)

        res = {
            "found_flags": list(self.found_flags),
            "visited": list(self.visited),
            "parents": dict(self.parent),
            "pages_crawled": self.pages_crawled,
            "fingerprints": list(self.seen_fps),
        }

        children_map = self._build_children_map()
        flags_map = {u: m for (u, m) in self.found_flags}
        self._print_pstree(children_map, flags_map, out_file="pstree.txt")

        with open("visited.txt", "w", encoding="utf-8") as vf:
            for v in sorted(self.visited):
                vf.write(v + "\n")

        if self.enable_fingerprint:
            with open("fingerprints.txt", "w", encoding="utf-8") as ff:
                for f in sorted(self.seen_fps):
                    ff.write(f + "\n")

        print(f"[+] pages crawled: {res['pages_crawled']}; visited URLs: {len(res['visited'])}")
        if res["found_flags"]:
            print(f"[+] Found {len(res['found_flags'])} flag(s):")
            for url, matched in res["found_flags"]:
                print(f"  - {url} -> matched: {repr(matched)}")
                path = self.reconstruct_path(url)
                print("    path:")
                for p in path:
                    print("      ", p)
        else:
            print("[-] No flags found.")

        print("[+] pstree written to pstree.txt, visited URLs in visited.txt")
        if self.enable_fingerprint:
            print("[+] fingerprints written to fingerprints.txt")
        return res

def parse_args():
    p = argparse.ArgumentParser(description="spider.py - canonicalization + fingerprint dedupe + clean PSTree")
    p.add_argument("--start", required=True, help="Starting URL (include scheme)")
    p.add_argument("--workers", type=int, default=10, help="Worker threads")
    p.add_argument("--max-pages", type=int, default=1000, help="Ceiling on pages to crawl")
    p.add_argument("--timeout", type=int, default=8, help="HTTP request timeout")
    p.add_argument("--rate-delay", type=float, default=0.0, help="Per-request delay per worker (seconds)")
    p.add_argument("--idle-timeout", type=float, default=10.0, help="Idle seconds before exit")
    p.add_argument("--stop-on-first", action="store_true", help="Stop when first flag is found")
    p.add_argument("--no-stop", dest="stop_on_first", action="store_false", help="Do not stop on flag")
    p.add_argument("--verify-ssl", action="store_true", default=False, help="Verify SSL certs")
    p.add_argument("--header", action="append", help="Custom header 'Name: value' (repeatable)")
    p.add_argument("--cookie", action="append", help="Cookie 'name=value' (repeatable)")
    p.add_argument("--pattern", action="append", help="Custom flag regex (repeatable)")
    p.add_argument("--enable-fingerprint", action="store_true", help="Enable fingerprint dedupe")
    p.add_argument("--fingerprint-length", type=int, default=2000, help="Fingerprint snippet length")
    p.add_argument("--use-psutil", action="store_true", help="Use psutil for TCP activity checks")
    p.add_argument("--no-strip-tracking", dest="strip_tracking", action="store_false", help="Do NOT strip tracking params")
    return p.parse_args()

def parse_kv_list(kv_list):
    d = {}
    if not kv_list:
        return d
    for kv in kv_list:
        if ":" in kv:
            k, v = kv.split(":", 1)
            d[k.strip()] = v.strip()
        elif "=" in kv:
            k, v = kv.split("=", 1)
            d[k.strip()] = v.strip()
    return d

if __name__ == "__main__":
    args = parse_args()
    headers = {"User-Agent": "CTFSpider/4.0"}
    if args.header:
        headers.update(parse_kv_list(args.header))
    cookies = {}
    if args.cookie:
        cookies.update(parse_kv_list(args.cookie))

    spider = Spider(
        start_url=args.start,
        workers=args.workers,
        max_pages=args.max_pages,
        timeout=args.timeout,
        rate_delay=args.rate_delay,
        flag_patterns=args.pattern,
        stop_on_first=args.stop_on_first,
        verify_ssl=args.verify_ssl,
        headers=headers,
        cookies=cookies,
        idle_timeout=args.idle_timeout,
        enable_fingerprint=args.enable_fingerprint,
        fingerprint_length=args.fingerprint_length,
        use_psutil=args.use_psutil,
        strip_tracking=args.strip_tracking,
    )

    print(f"[+] starting spider: {args.start} (origin: {spider.base_origin}); fingerprint={spider.enable_fingerprint}; psutil={spider.use_psutil}")
    spider.run()
    ```

    Using script 
    
    ```python3 better_chall16.py  --start http://web-16.challs.olicyber.it/ \
  --workers 12 \
  --max-pages 2000 \
  --timeout 6 \
  --rate-delay 0.05 \
  --idle-timeout 4
```

We get  a complete tree of the site 

``` 
=== PSTREE ===
http://web-16.challs.olicyber.it/
    ├── http://web-16.challs.olicyber.it/page?p=2024270
    │   ├── http://web-16.challs.olicyber.it/page?p=2321532
    │   │   ├── http://web-16.challs.olicyber.it/page?p=2475837
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1362100
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8478455
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=4118726
/    
/
/
/
            └── http://web-16.challs.olicyber.it/page?p=2290230
                ├── http://web-16.challs.olicyber.it/page?p=1110461
                │   └── http://web-16.challs.olicyber.it/page?p=4418935
                ├── http://web-16.challs.olicyber.it/page?p=36162
                └── http://web-16.challs.olicyber.it/page?p=6685150
                    ├── http://web-16.challs.olicyber.it/page?p=4679640
                    └── http://web-16.challs.olicyber.it/page?p=9269833
[+] pages crawled: 1001; visited URLs: 1001
[+] Found 1 flag(s):
  - http://web-16.challs.olicyber.it/page?p=4558624 -> matched: 'flag{n0wh3r3_i5_54f3}'
```


We have completed this challenge using a very complex and simple script


## Note 



we are also provided the web server code in challenge.py. We can see that the challenge is written in flask and spins up a web page with 1, 10000000 pages and places the flag in one

