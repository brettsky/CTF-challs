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
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=4482414
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=205780
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3679592
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2995871
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=2597060
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8398442
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6838383
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=7389841
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6705063
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7411940
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3078419
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7550918
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3816535
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=463061
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9580514
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1935114
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3327422
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1164687
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5507322
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3514945
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9680809
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=2641283
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=7078000
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=7321475
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=3340846
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=4785688
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=8153567
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=2037192
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=445200
    │   │   │       │       └── http://web-16.challs.olicyber.it/page?p=6374123
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=8823995
    │   │   ├── http://web-16.challs.olicyber.it/page?p=3197912
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3717771
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1867826
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2195774
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9224174
    │   │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1839608
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5266631
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9344067
    │   │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=4107777
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=4163954
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5213523
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1264749
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1429099
    │   │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3165062
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5144281
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3946067
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8249790
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4408073
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9872387
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4456273
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5866295
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8125901
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=843637
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5790219
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1721136
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6960329
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4833598
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5551269
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=615676
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=1044646
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6358114
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1970755
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7938747
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3226068
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=4743228
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7963716
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5539838
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8361354
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=1065819
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9261705
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=2135535
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=1651178
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=247596
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=8990306
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5363837
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2222253
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5022742
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7640616
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=604452
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9416130
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6194417
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7852575
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=6850945
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=8546410
    │   │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=162231
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=2564218
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=9029843
    │   │   │   │           └── http://web-16.challs.olicyber.it/page?p=3612366
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7658159
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1626230
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2916108
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1022699
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=861959
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5423635
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7930104
    │   │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=5891255
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8753458
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=7935170
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5440562
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1903562
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=641850
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9117244
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7187927
    │   │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=4049283
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=971824
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=59487
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3681285
    │   │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5307806
    │   │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3768845
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7939994
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6970772
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4171762
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9799227
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9673543
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=1813544
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=2484602
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=3630332
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=1194199
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=9314312
    │   │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=7159522
    │   │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=768806
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=8877066
    │   │   │   │       │       └── http://web-16.challs.olicyber.it/page?p=2607984
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=959075
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=9940075
    │   │   │   │           └── http://web-16.challs.olicyber.it/page?p=9445466
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9265242
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7072685
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4213116
    │   │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4661908
    │   │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=2154052
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8548433
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4232414
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5098176
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6360683
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5338113
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5276723
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7231839
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=7987517
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7090294
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=3840715
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=4006493
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5543671
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=6542891
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=7665982
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9712651
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5770620
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=2237059
    │   │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=5672135
    │   │   │       │   │       └── http://web-16.challs.olicyber.it/page?p=2276660
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=2500716
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=3526281
    │   │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=7387113
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=3576136
    │   │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=6358386
    │   │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=6722756
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=4528973
    │   │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=2608514
    │   │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=7138770
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=5724910
    │   │   │       │       ├── http://web-16.challs.olicyber.it/page?p=1140195
    │   │   │       │       ├── http://web-16.challs.olicyber.it/page?p=2386329
    │   │   │       │       └── http://web-16.challs.olicyber.it/page?p=6273234
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=6718474
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=1217072
    │   │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=8961381
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=1477399
    │   │   │       │       └── http://web-16.challs.olicyber.it/page?p=7713147
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=8164992
    │   │   │           ├── http://web-16.challs.olicyber.it/page?p=2320822
    │   │   │           ├── http://web-16.challs.olicyber.it/page?p=2955088
    │   │   │           └── http://web-16.challs.olicyber.it/page?p=3761824
    │   │   │               └── http://web-16.challs.olicyber.it/page?p=649692
    │   │   ├── http://web-16.challs.olicyber.it/page?p=4480461
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2768992
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2342609
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7306262
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6534337
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3656839
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6897152
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4476258
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6381735
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9990033
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3700026
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=257490
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9351718
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=1436348
    │   │   ├── http://web-16.challs.olicyber.it/page?p=6110623
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1582525
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6851697
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=1642636
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7194571
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9873814
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=212268
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3769796
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4936454
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6640185
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=6751159
    │   │   │   │           └── http://web-16.challs.olicyber.it/page?p=520597
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5261416
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7670956
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9540020
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=8147707
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=3348277
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=4886521
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=6425185
    │   │   ├── http://web-16.challs.olicyber.it/page?p=728978
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1173966
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1171219
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=1622632
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=4081984
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3240181
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1564690
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=1818693
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2684053
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6089807
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4299056
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8626109
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6360308
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=701772
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=2939213
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5452833
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7519122
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8312591
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=848732
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4041155
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4673213
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8143904
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8647850
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=4074337
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9304683
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=1229111
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5038572
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=9418195
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5708457
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=7210625
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=486956
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=8214802
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2086309
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2090866
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4382464
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8897859
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8293087
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8910818
    │   │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5591987
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8580256
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9494773
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3823499
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3335943
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3558781
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7294151
    │   │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=6818497
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4960272
    │   │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1677408
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7312115
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9241546
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=9983033
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4569245
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5233775
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7883824
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8937327
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6117838
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=675420
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7707871
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8196977
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=954281
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9468927
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9660267
    │   │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=4200477
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=484349
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9807726
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=5952976
    │   │   │   │           └── http://web-16.challs.olicyber.it/page?p=9214377
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2762153
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=409791
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1259380
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4672074
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=790482
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6067229
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8996415
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4148726
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4024270
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9035883
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4137723
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9069561
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9362912
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=8907392
    │   │   │   │   │           └── http://web-16.challs.olicyber.it/page?p=9192861
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=481507
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4147995
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=1161194
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4440026
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5171717
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2871231
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8363327
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9033726
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7307728
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1437027
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3256753
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4456574
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=739654
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=1556018
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5492067
    │   │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=9293262
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=6780933
    │   │   │   │           └── http://web-16.challs.olicyber.it/page?p=3671546
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4437924
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1191067
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5323377
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=981187
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=2418527
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1770649
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=732281
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3698380
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9042539
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2219825
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4394881
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5075396
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9283823
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9717033
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7935225
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=4579095
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=5398529
    │   │   │   │           └── http://web-16.challs.olicyber.it/page?p=7344376
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6191136
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4606981
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2919695
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3305701
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4013880
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8095000
    │   │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3971794
    │   │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6477327
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7558379
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8526868
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7574681
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=1876829
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=3524500
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=6523942
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=9281591
    │   │   │   │       ├── http://web-16.challs.olicyber.it/page?p=938484
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=9983183
    │   │   │   │           └── http://web-16.challs.olicyber.it/page?p=3585315
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=7741811
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=3841006
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=1344048
    │   │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=54448
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=4453787
    │   │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=7890440
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=6844948
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=7175396
    │   │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=1349591
    │   │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=7755440
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=7835374
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5407659
    │   │   │       │   ├── http://web-16.challs.olicyber.it/page?p=8396530
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=9008868
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=9029044
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=98920
    │   │   │           ├── http://web-16.challs.olicyber.it/page?p=1375454
    │   │   │           └── http://web-16.challs.olicyber.it/page?p=527022
    │   │   │               ├── http://web-16.challs.olicyber.it/page?p=109032
    │   │   │               │   └── http://web-16.challs.olicyber.it/page?p=93027
    │   │   │               └── http://web-16.challs.olicyber.it/page?p=8436430
    │   │   ├── http://web-16.challs.olicyber.it/page?p=7418211
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1166942
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7106471
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=7053919
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1876933
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4235885
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=2194790
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=1077582
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4443952
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1156903
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4663624
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5960454
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2970446
    │   │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=2678639
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=415847
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7082669
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=6783309
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=5472442
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5933743
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=4901240
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=666755
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=8997382
    │   │   │           ├── http://web-16.challs.olicyber.it/page?p=3867787
    │   │   │           ├── http://web-16.challs.olicyber.it/page?p=5159231
    │   │   │           └── http://web-16.challs.olicyber.it/page?p=8132115
    │   │   └── http://web-16.challs.olicyber.it/page?p=9997349
    │   │       ├── http://web-16.challs.olicyber.it/page?p=5837818
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=6022675
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=7875174
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=6402510
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=6550191
    │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=6076507
    │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=914795
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=9906821
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=8235578
    │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=3771677
    │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=4428915
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=4970191
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=9850289
    │   │       │       ├── http://web-16.challs.olicyber.it/page?p=1785278
    │   │       │       ├── http://web-16.challs.olicyber.it/page?p=9046845
    │   │       │       │   └── http://web-16.challs.olicyber.it/page?p=4545224
    │   │       │       └── http://web-16.challs.olicyber.it/page?p=9740680
    │   │       ├── http://web-16.challs.olicyber.it/page?p=7425150
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=4449369
    │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=4091350
    │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=6812811
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=7639415
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=6328535
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=4587309
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=7367773
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=3470106
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=9930313
    │   │       └── http://web-16.challs.olicyber.it/page?p=8633493
    │   │           ├── http://web-16.challs.olicyber.it/page?p=3539705
    │   │           │   ├── http://web-16.challs.olicyber.it/page?p=452422
    │   │           │   └── http://web-16.challs.olicyber.it/page?p=8961108
    │   │           │       └── http://web-16.challs.olicyber.it/page?p=8767313
    │   │           ├── http://web-16.challs.olicyber.it/page?p=4842083
    │   │           │   └── http://web-16.challs.olicyber.it/page?p=2564252
    │   │           └── http://web-16.challs.olicyber.it/page?p=621087
    │   ├── http://web-16.challs.olicyber.it/page?p=4438491
    │   │   ├── http://web-16.challs.olicyber.it/page?p=1262383
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1686549
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3117626
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7190930
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4130809
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5406445
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7793854
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8517486
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5483563
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9377211
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9658156
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5229732
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1338688
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=341920
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9020009
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5767293
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1275010
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9191767
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7698257
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=7606963
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=1130790
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5871361
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=9113686
    │   │   ├── http://web-16.challs.olicyber.it/page?p=6366206
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2653447
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2815035
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=28375
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3694635
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9686362
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3769852
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3213525
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3551071
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7351518
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=865902
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9047887
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=2530519
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=2634981
    │   │   └── http://web-16.challs.olicyber.it/page?p=6728340
    │   │       ├── http://web-16.challs.olicyber.it/page?p=237371
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=5825113
    │   │       └── http://web-16.challs.olicyber.it/page?p=7633774
    │   │           ├── http://web-16.challs.olicyber.it/page?p=430813
    │   │           │   └── http://web-16.challs.olicyber.it/page?p=7096888
    │   │           └── http://web-16.challs.olicyber.it/page?p=983739
    │   │               └── http://web-16.challs.olicyber.it/page?p=499915
    │   ├── http://web-16.challs.olicyber.it/page?p=7416217
    │   │   ├── http://web-16.challs.olicyber.it/page?p=1151226
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1936572
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3903403
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6210607
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2030967
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6120869
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6654758
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9259638
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=8487337
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=8224220
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=9049279
    │   │   ├── http://web-16.challs.olicyber.it/page?p=1664864
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3218543
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5009889
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6350754
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9772889
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3231029
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=19312
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4531231
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7315832
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3594298
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4108604
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4334435
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4770423
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7132770
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6417986
    │   │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=7663606
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7801976
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4348513
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7816913
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8123505
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9895028
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=2646553
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4682941
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3415141
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2592975
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7863448
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7761612
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7491823
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5386464
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7419379
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9096527
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=1321325
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=325198
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=4745251
    │   │   │           └── http://web-16.challs.olicyber.it/page?p=2747535
    │   │   ├── http://web-16.challs.olicyber.it/page?p=3533780
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3486103
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3050767
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7106423
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4691891
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7722607
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6975535
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7030011
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=8002393
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=8722816
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=5799668
    │   │   └── http://web-16.challs.olicyber.it/page?p=9153487
    │   │       ├── http://web-16.challs.olicyber.it/page?p=1754895
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=2741439
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=1914065
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=9393287
    │   │       ├── http://web-16.challs.olicyber.it/page?p=4558624  [FLAG: flag{n0wh3r3_i5_54f3}]
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=7563203
    │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=1563791
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=987738
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=8427048
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=9285736
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=9847181
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=9962499
    │   │       ├── http://web-16.challs.olicyber.it/page?p=4635018
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=3567282
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=5097515
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=9482935
    │   │       │       └── http://web-16.challs.olicyber.it/page?p=4234551
    │   │       ├── http://web-16.challs.olicyber.it/page?p=4668372
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=6637602
    │   │       │       └── http://web-16.challs.olicyber.it/page?p=5549758
    │   │       ├── http://web-16.challs.olicyber.it/page?p=744683
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=3262082
    │   │       │   │   ├── http://web-16.challs.olicyber.it/page?p=2426690
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=8961300
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=6610563
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=9667228
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=9792397
    │   │       │       └── http://web-16.challs.olicyber.it/page?p=8996208
    │   │       └── http://web-16.challs.olicyber.it/page?p=7971466
    │   │           ├── http://web-16.challs.olicyber.it/page?p=3744855
    │   │           └── http://web-16.challs.olicyber.it/page?p=6693980
    │   ├── http://web-16.challs.olicyber.it/page?p=7999184
    │   │   └── http://web-16.challs.olicyber.it/page?p=3993056
    │   │       ├── http://web-16.challs.olicyber.it/page?p=1566778
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=8191132
    │   │       ├── http://web-16.challs.olicyber.it/page?p=5207975
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=8234616
    │   │       ├── http://web-16.challs.olicyber.it/page?p=6054580
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=2109912
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=3860685
    │   │       │       └── http://web-16.challs.olicyber.it/page?p=2770371
    │   │       │           └── http://web-16.challs.olicyber.it/page?p=3185958
    │   │       └── http://web-16.challs.olicyber.it/page?p=9281553
    │   └── http://web-16.challs.olicyber.it/page?p=9870183
    │       ├── http://web-16.challs.olicyber.it/page?p=3652415
    │       │   ├── http://web-16.challs.olicyber.it/page?p=6073293
    │       │   ├── http://web-16.challs.olicyber.it/page?p=7412770
    │       │   │   ├── http://web-16.challs.olicyber.it/page?p=7896869
    │       │   │   │   └── http://web-16.challs.olicyber.it/page?p=6933144
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=8801947
    │       │   └── http://web-16.challs.olicyber.it/page?p=7945037
    │       │       ├── http://web-16.challs.olicyber.it/page?p=1408405
    │       │       ├── http://web-16.challs.olicyber.it/page?p=3589534
    │       │       └── http://web-16.challs.olicyber.it/page?p=7750677
    │       │           └── http://web-16.challs.olicyber.it/page?p=4217854
    │       ├── http://web-16.challs.olicyber.it/page?p=6435506
    │       │   ├── http://web-16.challs.olicyber.it/page?p=2141240
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=7132649
    │       │   ├── http://web-16.challs.olicyber.it/page?p=2846950
    │       │   │   ├── http://web-16.challs.olicyber.it/page?p=5623526
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=6982242
    │       │   └── http://web-16.challs.olicyber.it/page?p=5569947
    │       │       └── http://web-16.challs.olicyber.it/page?p=7481189
    │       ├── http://web-16.challs.olicyber.it/page?p=6462507
    │       │   ├── http://web-16.challs.olicyber.it/page?p=6754865
    │       │   │   ├── http://web-16.challs.olicyber.it/page?p=7033427
    │       │   │   │   └── http://web-16.challs.olicyber.it/page?p=2583207
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=7630713
    │       │   ├── http://web-16.challs.olicyber.it/page?p=7312937
    │       │   │   ├── http://web-16.challs.olicyber.it/page?p=1530794
    │       │   │   │   └── http://web-16.challs.olicyber.it/page?p=131250
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=4666693
    │       │   ├── http://web-16.challs.olicyber.it/page?p=7379838
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=908842
    │       │   ├── http://web-16.challs.olicyber.it/page?p=8279822
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=2545557
    │       │   └── http://web-16.challs.olicyber.it/page?p=8937983
    │       │       ├── http://web-16.challs.olicyber.it/page?p=6811
    │       │       │   └── http://web-16.challs.olicyber.it/page?p=5294017
    │       │       └── http://web-16.challs.olicyber.it/page?p=7612583
    │       └── http://web-16.challs.olicyber.it/page?p=7558198
    │           ├── http://web-16.challs.olicyber.it/page?p=120643
    │           │   ├── http://web-16.challs.olicyber.it/page?p=2783723
    │           │   │   └── http://web-16.challs.olicyber.it/page?p=6774230
    │           │   └── http://web-16.challs.olicyber.it/page?p=4364699
    │           ├── http://web-16.challs.olicyber.it/page?p=3786402
    │           │   ├── http://web-16.challs.olicyber.it/page?p=7612221
    │           │   └── http://web-16.challs.olicyber.it/page?p=8179731
    │           │       └── http://web-16.challs.olicyber.it/page?p=3740037
    │           │           └── http://web-16.challs.olicyber.it/page?p=2626182
    │           ├── http://web-16.challs.olicyber.it/page?p=3965790
    │           │   ├── http://web-16.challs.olicyber.it/page?p=5123431
    │           │   └── http://web-16.challs.olicyber.it/page?p=5855397
    │           ├── http://web-16.challs.olicyber.it/page?p=6296606
    │           └── http://web-16.challs.olicyber.it/page?p=7273316
    │               ├── http://web-16.challs.olicyber.it/page?p=1813597
    │               └── http://web-16.challs.olicyber.it/page?p=8874153
    │                   └── http://web-16.challs.olicyber.it/page?p=6817882
    │                       └── http://web-16.challs.olicyber.it/page?p=9891627
    ├── http://web-16.challs.olicyber.it/page?p=8518425
    │   ├── http://web-16.challs.olicyber.it/page?p=2710344
    │   │   ├── http://web-16.challs.olicyber.it/page?p=4017344
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1987288
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5271131
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7973916
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5639318
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6455325
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2351869
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=454697
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5944127
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8310236
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1422634
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1453963
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5101804
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9730530
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9800874
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=8075855
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=8375711
    │   │   ├── http://web-16.challs.olicyber.it/page?p=4641924
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1374159
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7796515
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9255662
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2030114
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8770839
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5702161
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3426901
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=5008936
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=8508104
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=2094236
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=4089127
    │   │   ├── http://web-16.challs.olicyber.it/page?p=4667266
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1724591
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5662320
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9756884
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2341058
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5304574
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4502930
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1571946
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7885466
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9324246
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=3918528
    │   │   ├── http://web-16.challs.olicyber.it/page?p=5279419
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=8537456
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=4988758
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=6069651
    │   │   ├── http://web-16.challs.olicyber.it/page?p=6377460
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8250139
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9667821
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=2117637
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=229420
    │   │   ├── http://web-16.challs.olicyber.it/page?p=775338
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3044883
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1525207
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6853788
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=4896625
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=5902402
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=4614227
    │   │   │           └── http://web-16.challs.olicyber.it/page?p=668753
    │   │   └── http://web-16.challs.olicyber.it/page?p=8689890
    │   │       ├── http://web-16.challs.olicyber.it/page?p=3374755
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=1096281
    │   │       └── http://web-16.challs.olicyber.it/page?p=3415797
    │   │           ├── http://web-16.challs.olicyber.it/page?p=6953167
    │   │           ├── http://web-16.challs.olicyber.it/page?p=7434501
    │   │           └── http://web-16.challs.olicyber.it/page?p=9593173
    │   ├── http://web-16.challs.olicyber.it/page?p=6003043
    │   │   ├── http://web-16.challs.olicyber.it/page?p=1561177
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=6829333
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=1532211
    │   │   └── http://web-16.challs.olicyber.it/page?p=5120254
    │   │       ├── http://web-16.challs.olicyber.it/page?p=2503121
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=5647120
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=4076818
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=9515703
    │   │       ├── http://web-16.challs.olicyber.it/page?p=3093110
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=5634587
    │   │       ├── http://web-16.challs.olicyber.it/page?p=4107246
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=9301498
    │   │       └── http://web-16.challs.olicyber.it/page?p=9233987
    │   │           ├── http://web-16.challs.olicyber.it/page?p=1940215
    │   │           ├── http://web-16.challs.olicyber.it/page?p=3010530
    │   │           ├── http://web-16.challs.olicyber.it/page?p=3586085
    │   │           └── http://web-16.challs.olicyber.it/page?p=9062251
    │   ├── http://web-16.challs.olicyber.it/page?p=7047417
    │   │   ├── http://web-16.challs.olicyber.it/page?p=3916202
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4374923
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6705491
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4761146
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5007073
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=2728883
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8517170
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7746015
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=1322048
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=873852
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=348051
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=7536478
    │   │   │           └── http://web-16.challs.olicyber.it/page?p=3934150
    │   │   ├── http://web-16.challs.olicyber.it/page?p=4652513
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2253032
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=1833231
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2997282
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7099077
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8197444
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=5577417
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7350100
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8196205
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7628589
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4180854
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5573148
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9631200
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=9324627
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=2493018
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9549710
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=2698194
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=6381685
    │   │   ├── http://web-16.challs.olicyber.it/page?p=4918716
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2657145
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3940442
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3684532
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5716098
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=433941
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1016912
    │   │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3731819
    │   │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4602181
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9557568
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=8576077
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=9049950
    │   │   ├── http://web-16.challs.olicyber.it/page?p=689026
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1694523
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5049102
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7186991
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2670227
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1000561
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=43038
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=1795766
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=533225
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8745960
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=7212327
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=1351869
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9548002
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=2138182
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=6891663
    │   │   ├── http://web-16.challs.olicyber.it/page?p=7799288
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2472190
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=327692
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=763627
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=4638894
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=538553
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6907401
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=7427626
    │   │   ├── http://web-16.challs.olicyber.it/page?p=8284510
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3553385
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=8130189
    │   │   └── http://web-16.challs.olicyber.it/page?p=9933754
    │   │       ├── http://web-16.challs.olicyber.it/page?p=4273535
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=6217148
    │   │       └── http://web-16.challs.olicyber.it/page?p=9650240
    │   │           └── http://web-16.challs.olicyber.it/page?p=3818419
    │   ├── http://web-16.challs.olicyber.it/page?p=8697970
    │   │   ├── http://web-16.challs.olicyber.it/page?p=2566766
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=170308
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4781296
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2551904
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=6199636
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5407374
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2123710
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=4186415
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9729500
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=674976
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=1871535
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=8014966
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9595
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=9103210
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=6189035
    │   │   ├── http://web-16.challs.olicyber.it/page?p=4835493
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2556552
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1944842
    │   │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6700829
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=8479357
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5071209
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5292424
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=4813614
    │   │   │   │       └── http://web-16.challs.olicyber.it/page?p=326766
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7048839
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=909394
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=1074177
    │   │   │       │   └── http://web-16.challs.olicyber.it/page?p=6395998
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=5188936
    │   │   └── http://web-16.challs.olicyber.it/page?p=9461840
    │   │       ├── http://web-16.challs.olicyber.it/page?p=2499628
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=1921860
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=4093380
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=6917153
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=4521645
    │   │       ├── http://web-16.challs.olicyber.it/page?p=4855125
    │   │       ├── http://web-16.challs.olicyber.it/page?p=5262633
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=7688756
    │   │       ├── http://web-16.challs.olicyber.it/page?p=5901534
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=3048908
    │   │       └── http://web-16.challs.olicyber.it/page?p=9059388
    │   │           ├── http://web-16.challs.olicyber.it/page?p=3188993
    │   │           ├── http://web-16.challs.olicyber.it/page?p=4159167
    │   │           ├── http://web-16.challs.olicyber.it/page?p=4727086
    │   │           └── http://web-16.challs.olicyber.it/page?p=7038375
    │   ├── http://web-16.challs.olicyber.it/page?p=8852898
    │   │   ├── http://web-16.challs.olicyber.it/page?p=1788239
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2670897
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=5137285
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=4449325
    │   │   │       ├── http://web-16.challs.olicyber.it/page?p=5692554
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=8683482
    │   │   ├── http://web-16.challs.olicyber.it/page?p=2790238
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=2563647
    │   │   ├── http://web-16.challs.olicyber.it/page?p=2950889
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2710896
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=9820202
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3905583
    │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=3879924
    │   │   │   ├── http://web-16.challs.olicyber.it/page?p=5555773
    │   │   │   └── http://web-16.challs.olicyber.it/page?p=8111743
    │   │   │       └── http://web-16.challs.olicyber.it/page?p=4446913
    │   │   │           └── http://web-16.challs.olicyber.it/page?p=8910915
    │   │   └── http://web-16.challs.olicyber.it/page?p=5059718
    │   │       ├── http://web-16.challs.olicyber.it/page?p=4437002
    │   │       │   ├── http://web-16.challs.olicyber.it/page?p=6361003
    │   │       │   │   └── http://web-16.challs.olicyber.it/page?p=1149598
    │   │       │   └── http://web-16.challs.olicyber.it/page?p=8294273
    │   │       └── http://web-16.challs.olicyber.it/page?p=8147721
    │   │           ├── http://web-16.challs.olicyber.it/page?p=1010497
    │   │           └── http://web-16.challs.olicyber.it/page?p=3337175
    │   └── http://web-16.challs.olicyber.it/page?p=9162580
    │       ├── http://web-16.challs.olicyber.it/page?p=3205395
    │       │   ├── http://web-16.challs.olicyber.it/page?p=4476584
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=1709621
    │       │   ├── http://web-16.challs.olicyber.it/page?p=842525
    │       │   │   ├── http://web-16.challs.olicyber.it/page?p=4031967
    │       │   │   │   └── http://web-16.challs.olicyber.it/page?p=6264957
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=9142601
    │       │   ├── http://web-16.challs.olicyber.it/page?p=8519949
    │       │   │   ├── http://web-16.challs.olicyber.it/page?p=3194549
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=5533188
    │       │   │       └── http://web-16.challs.olicyber.it/page?p=3344718
    │       │   └── http://web-16.challs.olicyber.it/page?p=8667567
    │       │       ├── http://web-16.challs.olicyber.it/page?p=1925627
    │       │       │   └── http://web-16.challs.olicyber.it/page?p=5707198
    │       │       ├── http://web-16.challs.olicyber.it/page?p=4004486
    │       │       │   └── http://web-16.challs.olicyber.it/page?p=9248694
    │       │       ├── http://web-16.challs.olicyber.it/page?p=4098413
    │       │       │   └── http://web-16.challs.olicyber.it/page?p=3883527
    │       │       └── http://web-16.challs.olicyber.it/page?p=5438437
    │       │           └── http://web-16.challs.olicyber.it/page?p=3668137
    │       ├── http://web-16.challs.olicyber.it/page?p=7893694
    │       │   ├── http://web-16.challs.olicyber.it/page?p=3191176
    │       │   │   ├── http://web-16.challs.olicyber.it/page?p=1683839
    │       │   │   └── http://web-16.challs.olicyber.it/page?p=2118061
    │       │   └── http://web-16.challs.olicyber.it/page?p=5643799
    │       └── http://web-16.challs.olicyber.it/page?p=9229090
    │           ├── http://web-16.challs.olicyber.it/page?p=1242893
    │           │   └── http://web-16.challs.olicyber.it/page?p=6752973
    │           └── http://web-16.challs.olicyber.it/page?p=4163556
    │               └── http://web-16.challs.olicyber.it/page?p=3318856
    │                   └── http://web-16.challs.olicyber.it/page?p=7350369
    └── http://web-16.challs.olicyber.it/page?p=9103505
        ├── http://web-16.challs.olicyber.it/page?p=4014746
        │   ├── http://web-16.challs.olicyber.it/page?p=2198038
        │   │   └── http://web-16.challs.olicyber.it/page?p=7841506
        │   │       ├── http://web-16.challs.olicyber.it/page?p=4977932
        │   │       └── http://web-16.challs.olicyber.it/page?p=9708719
        │   ├── http://web-16.challs.olicyber.it/page?p=4832328
        │   │   ├── http://web-16.challs.olicyber.it/page?p=1154127
        │   │   ├── http://web-16.challs.olicyber.it/page?p=1672885
        │   │   ├── http://web-16.challs.olicyber.it/page?p=2118619
        │   │   └── http://web-16.challs.olicyber.it/page?p=6818733
        │   ├── http://web-16.challs.olicyber.it/page?p=5160870
        │   └── http://web-16.challs.olicyber.it/page?p=5752577
        │       ├── http://web-16.challs.olicyber.it/page?p=2396988
        │       │   └── http://web-16.challs.olicyber.it/page?p=9790058
        │       ├── http://web-16.challs.olicyber.it/page?p=289294
        │       │   └── http://web-16.challs.olicyber.it/page?p=4793723
        │       └── http://web-16.challs.olicyber.it/page?p=8488614
        │           └── http://web-16.challs.olicyber.it/page?p=7078674
        ├── http://web-16.challs.olicyber.it/page?p=5033116
        │   ├── http://web-16.challs.olicyber.it/page?p=3009173
        │   │   ├── http://web-16.challs.olicyber.it/page?p=352897
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=8031492
        │   │   ├── http://web-16.challs.olicyber.it/page?p=419611
        │   │   │   ├── http://web-16.challs.olicyber.it/page?p=6784726
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=7617382
        │   │   ├── http://web-16.challs.olicyber.it/page?p=4218029
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=6442090
        │   │   ├── http://web-16.challs.olicyber.it/page?p=5218368
        │   │   │   ├── http://web-16.challs.olicyber.it/page?p=7795420
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=9901585
        │   │   ├── http://web-16.challs.olicyber.it/page?p=7801208
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=6426266
        │   │   ├── http://web-16.challs.olicyber.it/page?p=9560491
        │   │   └── http://web-16.challs.olicyber.it/page?p=9886238
        │   │       └── http://web-16.challs.olicyber.it/page?p=2036060
        │   ├── http://web-16.challs.olicyber.it/page?p=397024
        │   │   ├── http://web-16.challs.olicyber.it/page?p=5596151
        │   │   ├── http://web-16.challs.olicyber.it/page?p=6961579
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=6906259
        │   │   └── http://web-16.challs.olicyber.it/page?p=899412
        │   │       ├── http://web-16.challs.olicyber.it/page?p=2726328
        │   │       └── http://web-16.challs.olicyber.it/page?p=4674184
        │   │           └── http://web-16.challs.olicyber.it/page?p=9136241
        │   ├── http://web-16.challs.olicyber.it/page?p=4002121
        │   │   ├── http://web-16.challs.olicyber.it/page?p=1188790
        │   │   ├── http://web-16.challs.olicyber.it/page?p=4924116
        │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2005796
        │   │   │   ├── http://web-16.challs.olicyber.it/page?p=3842789
        │   │   │   │   └── http://web-16.challs.olicyber.it/page?p=1458592
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=7290771
        │   │   └── http://web-16.challs.olicyber.it/page?p=7248239
        │   │       └── http://web-16.challs.olicyber.it/page?p=3147113
        │   ├── http://web-16.challs.olicyber.it/page?p=4634663
        │   │   ├── http://web-16.challs.olicyber.it/page?p=4747931
        │   │   ├── http://web-16.challs.olicyber.it/page?p=6730429
        │   │   ├── http://web-16.challs.olicyber.it/page?p=7922534
        │   │   └── http://web-16.challs.olicyber.it/page?p=9658482
        │   │       └── http://web-16.challs.olicyber.it/page?p=4567534
        │   ├── http://web-16.challs.olicyber.it/page?p=7526487
        │   │   ├── http://web-16.challs.olicyber.it/page?p=1548512
        │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1299955
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=4479145
        │   │   ├── http://web-16.challs.olicyber.it/page?p=3106299
        │   │   │   ├── http://web-16.challs.olicyber.it/page?p=1221855
        │   │   │   ├── http://web-16.challs.olicyber.it/page?p=2011364
        │   │   │   └── http://web-16.challs.olicyber.it/page?p=4491947
        │   │   └── http://web-16.challs.olicyber.it/page?p=3214349
        │   │       ├── http://web-16.challs.olicyber.it/page?p=156288
        │   │       └── http://web-16.challs.olicyber.it/page?p=547606
        │   └── http://web-16.challs.olicyber.it/page?p=9410456
        │       ├── http://web-16.challs.olicyber.it/page?p=1198059
        │       ├── http://web-16.challs.olicyber.it/page?p=1719584
        │       │   ├── http://web-16.challs.olicyber.it/page?p=669325
        │       │   └── http://web-16.challs.olicyber.it/page?p=9442882
        │       ├── http://web-16.challs.olicyber.it/page?p=1919137
        │       └── http://web-16.challs.olicyber.it/page?p=9974377
        │           ├── http://web-16.challs.olicyber.it/page?p=192620
        │           └── http://web-16.challs.olicyber.it/page?p=9232927
        │               └── http://web-16.challs.olicyber.it/page?p=852265
        └── http://web-16.challs.olicyber.it/page?p=5709939
            ├── http://web-16.challs.olicyber.it/page?p=1737894
            │   ├── http://web-16.challs.olicyber.it/page?p=44892
            │   │   ├── http://web-16.challs.olicyber.it/page?p=4191057
            │   │   └── http://web-16.challs.olicyber.it/page?p=7235970
            │   ├── http://web-16.challs.olicyber.it/page?p=8706769
            │   │   ├── http://web-16.challs.olicyber.it/page?p=1197936
            │   │   └── http://web-16.challs.olicyber.it/page?p=1921543
            │   ├── http://web-16.challs.olicyber.it/page?p=9149733
            │   │   └── http://web-16.challs.olicyber.it/page?p=1714804
            │   └── http://web-16.challs.olicyber.it/page?p=9260894
            │       ├── http://web-16.challs.olicyber.it/page?p=3540416
            │       └── http://web-16.challs.olicyber.it/page?p=9518670
            │           ├── http://web-16.challs.olicyber.it/page?p=841249
            │           └── http://web-16.challs.olicyber.it/page?p=8468773
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


