import re
import idna
import tldextract
import validators
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Tuple
import base64

URL_REGEX = re.compile(
    r'((?:https?://|ftp://|www\.)[^\s<>"\'\)\]]+)',
    re.IGNORECASE
)

SHORTENER_HOSTS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","is.gd","ow.ly","buff.ly","rebrand.ly",
    "t.ly","cutt.ly","rb.gy","shorturl.at","shorte.st"
}

RISKY_ATTACH_EXT = {".exe",".scr",".js",".vbs",".jse",".wsf",".ps1",".bat",".cmd",".com",
                    ".docm",".xlsm",".pptm",".zip",".rar",".7z",".iso",".img",".lnk"}

SUSP_TLDS = {"zip","mov","click","country","gq","ru","su","cm"}

def to_text(html_or_text: str) -> str:
    # If HTML-like, strip tags
    if "<html" in html_or_text.lower() or "</a>" in html_or_text.lower():
        soup = BeautifulSoup(html_or_text, "lxml")
        return soup.get_text(" ", strip=True)
    return html_or_text

def extract_urls(html_or_text: str) -> List[str]:
    # Find links in hrefs and plain text
    urls = set()
    if "<a " in html_or_text.lower():
        soup = BeautifulSoup(html_or_text, "lxml")
        for a in soup.find_all("a", href=True):
            urls.add(a["href"])
    for m in URL_REGEX.finditer(html_or_text):
        urls.add(m.group(1))
    # Normalize
    cleaned = []
    for u in urls:
        if u.lower().startswith("www."):
            u = "http://" + u
        # strip trailing punctuation
        u = u.rstrip(").,;!\"'")
        if validators.url(u):
            cleaned.append(u)
    return sorted(set(cleaned))

def is_ip_host(host: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) is not None

def host_parts(url: str) -> Tuple[str,str,str]:
    ext = tldextract.extract(url)
    domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
    return ext.subdomain, domain, ext.suffix

def is_shortener(host: str) -> bool:
    return host.lower() in SHORTENER_HOSTS

def looks_idn_punycode(host: str) -> bool:
    return host.startswith("xn--")

def decode_b64(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return s
