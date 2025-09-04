import re, time, os, json, socket
from typing import Dict, Any, List, Tuple, Optional
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
import dns.resolver
import whois
import requests
import tldextract
from .utils import extract_urls, host_parts, is_ip_host, is_shortener, looks_idn_punycode, to_text

DNS_TIMEOUT = 3.0
WHOIS_TIMEOUT = 5.0

def parse_eml_bytes(data: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(data)

def get_header(msg: EmailMessage, name: str) -> str:
    v = msg.get(name, "")
    return str(v)

def collect_headers(msg: EmailMessage) -> Dict[str, Any]:
    keys = ["From","To","Cc","Subject","Date","Message-ID","Reply-To","Return-Path",
            "Received","Authentication-Results","List-Unsubscribe"]
    d = {}
    for k in keys:
        vals = msg.get_all(k, [])
        d[k] = "\n".join([str(v) for v in vals]) if vals else ""
    return d

def body_text(msg: EmailMessage) -> Tuple[str,str]:
    text = ""
    html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                text += part.get_content()
            elif ctype == "text/html":
                html += part.get_content()
    else:
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            text = msg.get_content()
        elif ctype == "text/html":
            html = msg.get_content()
    return text, html

def list_attachments(msg: EmailMessage) -> List[Tuple[str, Optional[str]]]:
    items = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            ctype = part.get_content_type()
            items.append((filename or "(no-name)", ctype))
    return items

def dns_txt_lookup(name: str) -> List[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        resolver.timeout = DNS_TIMEOUT
        answers = resolver.resolve(name, "TXT")
        return [b"".join(r.strings).decode("utf-8","ignore") for r in answers]
    except Exception:
        return []

def has_spf(domain: str) -> Tuple[bool, str]:
    txts = dns_txt_lookup(domain)
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return True, t
    return False, ""

def get_dmarc_record(domain: str) -> Tuple[bool, str]:
    dmarc_domain = f"_dmarc.{domain}"
    txts = dns_txt_lookup(dmarc_domain)
    for t in txts:
        if t.lower().startswith("v=dmarc1"):
            return True, t
    return False, ""

def whois_domain(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        created = None
        if isinstance(w.creation_date, list):
            created = w.creation_date[0]
        else:
            created = w.creation_date
        registrar = w.registrar if hasattr(w, "registrar") else None
        return {"created": str(created) if created else None, "registrar": registrar}
    except Exception as e:
        return {"error": str(e)}

def vt_url_report(url: str) -> Dict[str, Any]:
    api = os.getenv("VT_API_KEY")
    if not api:
        return {}
    try:
        headers = {"x-apikey": api}
        # Normalize URL ID per VT v3 (URL must be base64url without padding)
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=6)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
            return {"vt_stats": stats}
        return {"error": f"VT status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def risk_rules(headers: Dict[str,str], urls: List[str], attachments: List[Tuple[str, Optional[str]]]) -> Tuple[int, List[Dict[str,Any]]]:
    score = 0
    reasons = []

    auth = headers.get("Authentication-Results","").lower()
    if "spf=fail" in auth: score += 15; reasons.append({"rule":"SPF fail","weight":15,"evidence":auth})
    if "dkim=fail" in auth or "dkim=none" in auth: score += 10; reasons.append({"rule":"DKIM fail/none","weight":10,"evidence":auth})
    if "dmarc=fail" in auth or "dmarc=none" in auth: score += 15; reasons.append({"rule":"DMARC fail/none","weight":15,"evidence":auth})

    from_h = headers.get("From","")
    reply = headers.get("Reply-To","")
    if reply and reply.split("@")[-1].strip(" >").lower() != from_h.split("@")[-1].strip(" >").lower():
        score += 10; reasons.append({"rule":"Reply-To mismatch","weight":10,"evidence":reply})

    subj = headers.get("Subject","").lower()
    if any(k in subj for k in ["urgent","verify","locked","payment","invoice","limited","gift","win"]):
        score += 5; reasons.append({"rule":"Urgent/pressure language","weight":5,"evidence":subj})

    # URL related rules
    for u in urls:
        host = tldextract.extract(u).fqdn
        if is_ip_host(host):
            score += 15; reasons.append({"rule":"URL uses raw IP","weight":15,"evidence":u})
        if is_shortener(host):
            score += 10; reasons.append({"rule":"URL shortener","weight":10,"evidence":host})
        if looks_idn_punycode(host):
            score += 10; reasons.append({"rule":"Punycode host","weight":10,"evidence":host})
        tld = host.split(".")[-1].lower()
        if tld in {"zip","mov","click"}:
            score += 5; reasons.append({"rule":"Suspicious TLD","weight":5,"evidence":tld})

    # Attachment rules
    for fname, ctype in attachments:
        lower = (fname or "").lower()
        for bad in [".exe",".js",".vbs",".scr",".docm",".xlsm",".pptm",".zip",".iso"]:
            if lower.endswith(bad):
                score += 20; reasons.append({"rule":"Risky attachment","weight":20,"evidence":fname})

    # Cap and normalize
    score = min(100, score)
    return score, reasons

def analyze_eml_bytes(data: bytes) -> Dict[str, Any]:
    msg = parse_eml_bytes(data)
    headers = collect_headers(msg)
    text, html = body_text(msg)
    body = html if html.strip() else text
    urls = extract_urls(body or "")
    atts = list_attachments(msg)

    # DNS info for From domain
    from_h = headers.get("From","")
    domain = ""
    m = re.search(r'@([A-Za-z0-9\.\-\_]+)', from_h)
    if m:
        domain = m.group(1).strip().strip(">")
    spf_present, spf_txt = (False,"")
    dmarc_present, dmarc_txt = (False,"")
    if domain:
        spf_present, spf_txt = has_spf(domain)
        dmarc_present, dmarc_txt = get_dmarc_record(domain)

    # Whois for each unique URL domain (top 5)
    uniq_domains = []
    for u in urls:
        ext = tldextract.extract(u)
        d = ".".join(p for p in [ext.domain, ext.suffix] if p)
        if d and d not in uniq_domains:
            uniq_domains.append(d)
    whois_info = {}
    for d in uniq_domains[:5]:
        whois_info[d] = whois_domain(d)

    # Risk rules
    score, reasons = risk_rules(headers, urls, atts)

    # VT optional (first URL only to save quota)
    vt = {}
    if urls:
        vt = vt_url_report(urls[0])

    return {
        "headers": headers,
        "body_preview": (html or text)[:2000],
        "urls": urls,
        "attachments": atts,
        "dns": {
            "from_domain": domain or None,
            "spf_record_present": spf_present,
            "spf_record": spf_txt or None,
            "dmarc_record_present": dmarc_present,
            "dmarc_record": dmarc_txt or None,
        },
        "whois": whois_info,
        "risk": {
            "score": score,
            "reasons": reasons
        },
        "virustotal": vt
    }
