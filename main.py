import http
import ipaddress
import sys
import urllib.parse 


# Words phishers commonly use to create false urgency or mimic login flows.
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "confirm", "password", "credential", "webscr", "ebayisapi",
}
 
# TLDs frequently abused because they're free or cheap to register.
SUSPICIOUS_TLDS = {"zip", "review", "country", "kim", "cricket", "tk", "gq", "ml"}
 
# Common URL-shortening services (they hide the true destination).
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}
 
 
def is_ip_address(host: str) -> bool:
    """Return True if the host is a raw IP address instead of a domain."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
 
 
def extract_features(url: str) -> dict:
    """
    Extract a dictionary of features from a URL.
 
    Each feature is a signal that, on its own, is weak, but combined they
    paint a reliable picture. This dict is also the input you'd feed to an
    ML model later.
    """
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()
 
    # Count subdomains: "a.b.example.com" -> 2 subdomains before the domain.
    domain_parts = host.split(".")
    subdomain_count = max(len(domain_parts) - 2, 0)
 
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
 
    return {
        "url_length": len(url),
        "has_ip": is_ip_address(host),
        "has_at_symbol": "@" in url,
        "subdomain_count": subdomain_count,
        "has_hyphen_in_domain": "-" in host,
        "uses_https": parsed.scheme == "https",
        "is_shortened": host in SHORTENERS,
        "suspicious_tld": tld in SUSPICIOUS_TLDS,
        "suspicious_keywords": sum(k in full for k in SUSPICIOUS_KEYWORDS),
        "digit_count_in_domain": sum(c.isdigit() for c in host),
        "has_double_slash_in_path": "//" in path,
    }
 
 
def score_url(url: str) -> dict:
    """
    Turn features into a risk score (0-100) plus a list of reasons.
 
    The weights are hand-tuned. In the ML version, a trained model learns
    these weights from data instead of you assigning them.
    """
    f = extract_features(url)
    score = 0
    reasons = []
 
    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(f"[+{points}] {reason}")
 
    if f["has_ip"]:
        add(25, "Uses a raw IP address instead of a domain name")
    if f["has_at_symbol"]:
        add(20, "Contains '@' symbol (hides the real destination)")
    if f["url_length"] > 75:
        add(10, f"Unusually long URL ({f['url_length']} chars)")
    if f["subdomain_count"] >= 3:
        add(15, f"Many subdomains ({f['subdomain_count']}) — brand mimicry")
    if f["has_hyphen_in_domain"]:
        add(10, "Hyphen in domain (common in impersonation)")
    if not f["uses_https"]:
        add(10, "No HTTPS")
    if f["is_shortened"]:
        add(15, "URL shortener hides the true destination")
    if f["suspicious_tld"]:
        add(10, "Suspicious / frequently-abused TLD")
    if f["suspicious_keywords"] > 0:
        add(5 * f["suspicious_keywords"],
            f"{f['suspicious_keywords']} suspicious keyword(s) found")
    if f["digit_count_in_domain"] > 3:
        add(10, "Many digits in domain")
 
    score = min(score, 100)  # cap at 100
 
    if score >= 60:
        verdict = "HIGH RISK - likely phishing"
    elif score >= 30:
        verdict = "MEDIUM RISK - suspicious"
    else:
        verdict = "LOW RISK - probably safe"
 
    return {"url": url, "score": score, "verdict": verdict, "reasons": reasons}
 
 
def print_report(result: dict) -> None:
    print(f"\nURL:     {result['url']}")
    print(f"Score:   {result['score']}/100")
    print(f"Verdict: {result['verdict']}")
    if result["reasons"]:
        print("Reasons:")
        for r in result["reasons"]:
            print(f"   {r}")
    else:
        print("Reasons: none — no suspicious signals detected")
 
 
DEMO_URLS = [
    "https://www.google.com",
    "http://paypal-secure-login.verify-account.com/update",
    "http://192.168.0.5/login.php",
    "https://bit.ly/3xYzAbc",
    "http://secure@evil.com/bank",
    "https://github.com/user/repo",
]
 
 
def main():
    if len(sys.argv) > 1:
        print_report(score_url(sys.argv[1]))
    else:
        print("No URL given — running demo set.\n" + "=" * 50)
        for u in DEMO_URLS:
            print_report(score_url(u))
            print("-" * 50)
 
 
if __name__ == "__main__":
    main()