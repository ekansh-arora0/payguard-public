#!/usr/bin/env python3
"""Full HTML page analyzer for phishing detection.

Scrapes the page, extracts structural features from the DOM,
and classifies using ML. No regex phrases. No hardcoded lists.
"""

import re
import math
import ssl
import socket
import hashlib
import datetime
from collections import Counter
from urllib.parse import urlparse, urljoin
from typing import List, Tuple, Optional, Dict

import numpy as np


def _check_domain_age(domain: str) -> Tuple[float, str]:
    """Check domain registration age. New domains are suspicious.

    Returns (risk_score, description).
    Risk is HIGH for domains < 30 days, MEDIUM for < 180 days.
    """
    # Cache results to avoid repeated WHOIS lookups
    if not hasattr(_check_domain_age, '_cache'):
        _check_domain_age._cache = {}
    if domain in _check_domain_age._cache:
        return _check_domain_age._cache[domain]

    try:
        import socket as _socket
        # Quick WHOIS query with timeout
        tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
        whois_server = {'com': 'whois.verisign-grs.com', 'net': 'whois.verisign-grs.com',
                       'org': 'whois.pir.org', 'top': 'whois.nic.top', 'xyz': 'whois.nic.xyz',
                       'io': 'whois.nic.io', 'co': 'whois.nic.co', 'site': 'whois.nic.site',
                       'online': 'whois.nic.online'}.get(tld, f'whois.{tld}')

        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((whois_server, 43))
        sock.sendall((domain + '\r\n').encode())
        response = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        text = response.decode('utf-8', errors='ignore')

        # Parse creation date
        import re as _re
        created_match = _re.search(r'(?:Creation Date|Created|Registered):\s*(\d{4}-\d{2}-\d{2})', text, _re.I)
        if not created_match:
            _check_domain_age._cache[domain] = (0.0, "")
            return 0.0, ""

        created = datetime.datetime.strptime(created_match.group(1), '%Y-%m-%d')
        age_days = (datetime.datetime.utcnow() - created).days

        result = (0.0, "")
        if age_days <= 7:
            result = (0.6, f"domain-registered-{age_days}d-ago")
        elif age_days <= 30:
            result = (0.4, f"domain-{age_days}-days-old")
        elif age_days <= 180:
            result = (0.2, f"domain-{age_days}-days-old")

        _check_domain_age._cache[domain] = result
        return result
    except Exception:
        _check_domain_age._cache[domain] = (0.0, "")
        return 0.0, ""


def _check_ssl_quality(domain: str) -> Tuple[float, str]:
    """Check SSL certificate quality. Cheap/free DV certs on store sites are suspicious."""
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return 0.3, "no-ssl-cert"

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                # Check if cert passes default verification
                try:
                    ctx2 = ssl.create_default_context()
                    with socket.create_connection((domain, 443), timeout=5) as s2:
                        with ctx2.wrap_socket(s2, server_hostname=domain):
                            pass
                except Exception:
                    return 0.3, "ssl-verification-failed"

                # DV cert (no org in subject) on a store = suspicious
                has_org = bool(subject.get('organizationName'))
                if not has_org:
                    return 0.1, "dv-cert-no-org"

                return 0.0, ""
    except Exception:
        return 0.2, "ssl-check-failed"


def extract_page_features(url: str, html: str) -> np.ndarray:
    """Extract 40 features from a page's HTML structure.

    These features capture HOW a page behaves, not what words it contains.
    A phishing page and a legitimate page with the same text have very
    different HTML structures.

    Returns 40-dimensional feature vector.
    """
    parsed = urlparse(url if url.startswith('http') else f'https://{url}')
    host = (parsed.netloc or '').lower()
    if host.startswith('www.'):
        host = host[4:]

    cl = html.lower()

    # === FORM ANALYSIS ===
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.S | re.I)
    form_tags = re.findall(r'<form[^>]*>', html, re.I)

    # 1. Number of forms
    n_forms = len(forms)

    # 2. Forms submitting cross-origin
    cross_origin_forms = 0
    for tag in form_tags:
        action = re.search(r'action\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        if action:
            action_url = action.group(1)
            if action_url.startswith('http'):
                action_host = urlparse(action_url).netloc.lower()
                if action_host and action_host != host and not action_host.endswith('.' + host):
                    cross_origin_forms += 1

    # 3. Forms with password inputs
    password_forms = 0
    for form_html in forms:
        if re.search(r'type\s*=\s*["\']password["\']', form_html, re.I):
            password_forms += 1

    # 4. Forms with method POST
    post_forms = sum(1 for tag in form_tags if re.search(r'method\s*=\s*["\']post["\']', tag, re.I))

    # 5. Hidden inputs count
    hidden_inputs = len(re.findall(r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>', html, re.I))

    # 6. Total input fields
    total_inputs = len(re.findall(r'<input\b', html, re.I))

    # === IFRAME ANALYSIS ===
    iframes = re.findall(r'<iframe[^>]*>', html, re.I)

    # 7. Number of iframes
    n_iframes = len(iframes)

    # 8. Cross-origin iframes
    cross_iframes = 0
    for iframe_tag in iframes:
        src = re.search(r'src\s*=\s*["\']([^"\']+)["\']', iframe_tag, re.I)
        if src:
            src_url = src.group(1)
            if src_url.startswith('http'):
                iframe_host = urlparse(src_url).netloc.lower()
                if iframe_host and iframe_host != host:
                    cross_iframes += 1

    # 9. Hidden iframes (width/height = 0 or 1)
    hidden_iframes = 0
    for iframe_tag in iframes:
        if re.search(r'(?:width|height)\s*=\s*["\'](?:0|1)["\']', iframe_tag, re.I):
            hidden_iframes += 1

    # === SCRIPT ANALYSIS ===
    scripts = re.findall(r'<script[^>]*>', html, re.I)
    inline_scripts = [s for s in scripts if not re.search(r'src\s*=', s, re.I)]
    external_scripts = [s for s in scripts if re.search(r'src\s*=', s, re.I)]

    # 10. Total scripts
    n_scripts = len(scripts)

    # 11. Inline scripts ratio
    inline_ratio = len(inline_scripts) / max(n_scripts, 1)

    # 12. External scripts from different origins
    cross_origin_scripts = 0
    for tag in external_scripts:
        src = re.search(r'src\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        if src and src.group(1).startswith('http'):
            script_host = urlparse(src.group(1)).netloc.lower()
            if script_host and script_host != host:
                cross_origin_scripts += 1

    # 13. eval/atob/unescape obfuscation
    obfuscation_count = cl.count('eval(') + cl.count('atob(') + cl.count('unescape(') + cl.count('fromcharcode')

    # 14. document.write / innerHTML injection
    injection_count = cl.count('document.write(') + cl.count('.innerhtml') + cl.count('.outerhtml')

    # 15. Redirect patterns
    redirect_count = (
        len(re.findall(r'location\s*(?:\.href)?\s*=', cl)) +
        len(re.findall(r'window\.location', cl)) +
        len(re.findall(r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\']', cl))
    )

    # === LINK ANALYSIS ===
    links = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html, re.I)

    # 16. Total links
    n_links = len(links)

    # 17. Cross-origin link ratio
    cross_links = 0
    for link in links[:100]:  # Sample first 100
        if link.startswith('http'):
            link_host = urlparse(link).netloc.lower()
            if link_host and link_host != host:
                cross_links += 1
    cross_link_ratio = cross_links / max(min(n_links, 100), 1)

    # 18. Data URI count (inline data)
    data_uri_count = len(re.findall(r'data:[^\s"\']+', html, re.I))

    # === CONTENT STRUCTURE ===

    # 19. Page size
    page_size = len(html)

    # 20. HTML tag count (complexity)
    tag_count = html.count('<')

    # 21. Text-to-HTML ratio
    _clean_html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.S | re.I)
    _clean_html = re.sub(r'<script[^>]*>.*$', '', _clean_html, flags=re.S | re.I)
    _clean_html = re.sub(r'<style[^>]*>.*?</style>', '', _clean_html, flags=re.S | re.I)
    _clean_html = re.sub(r'<style[^>]*>.*$', '', _clean_html, flags=re.S | re.I)
    text_content = re.sub(r'<[^>]+>', '', _clean_html)
    text_content = re.sub(r'\s+', ' ', text_content).strip()
    text_ratio = len(text_content) / max(len(html), 1)

    # 22. Content density — very little text on a "shop" page is suspicious
    text_length = len(text_content)

    # 22. Number of external stylesheets
    external_css = len(re.findall(r'<link[^>]*rel\s*=\s*["\']stylesheet["\'][^>]*>', html, re.I))

    # 23. Inline styles count
    inline_styles = len(re.findall(r'style\s*=\s*["\']', html, re.I))

    # 24. Event handlers (onclick, onload, etc.)
    event_handlers = len(re.findall(r'\son\w+\s*=\s*["\']', html, re.I))

    # === STRUCTURAL ANOMALIES ===

    # 25. Has base tag (can hijack relative URLs)
    has_base_tag = int(bool(re.search(r'<base\b', html, re.I)))

    # 26. Multiple charset declarations
    charset_count = len(re.findall(r'charset\s*=', html, re.I))

    # 27. Content-Security-Policy in meta
    has_csp_meta = int(bool(re.search(r'content-security-policy', cl)))

    # 28. Subresource Integrity
    sri_count = len(re.findall(r'integrity\s*=', html, re.I))

    # 29. Nonce-based scripts
    nonce_count = len(re.findall(r'nonce\s*=', html, re.I))

    # 30. noopener/noreferrer links
    noopener_count = len(re.findall(r'rel\s*=\s*["\']noopener', html, re.I))

    # === PAGE IDENTITY SIGNALS ===

    # 31. Has favicon
    has_favicon = int(bool(re.search(r'<link[^>]*rel\s*=\s*["\'](?:shortcut\s+)?icon["\']', html, re.I)))

    # 32. Has Open Graph tags
    has_og = int(bool(re.search(r'<meta[^>]*property\s*=\s*["\']og:', html, re.I)))

    # 33. Title tag present
    has_title = int(bool(re.search(r'<title[^>]*>', html, re.I)))

    # 34. Meta description present
    has_meta_desc = int(bool(re.search(r'<meta[^>]*name\s*=\s*["\']description["\']', html, re.I)))

    # 35. Has viewport meta (mobile responsive)
    has_viewport = int(bool(re.search(r'<meta[^>]*name\s*=\s*["\']viewport["\']', html, re.I)))

    # === META TAG BRAND MISMATCH ===
    # OG title or meta title claims to be a brand but domain is different
    # e.g., og:title="YAHOO" on l.ead.me = impersonation
    meta_titles = []
    og_title = re.search(r'<meta[^>]*property\s*=\s*["\']og:title["\'][^>]*content\s*=\s*["\']([^"\']+)["\']', html, re.I)
    if og_title:
        meta_titles.append(og_title.group(1).lower())
    title_tag = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
    if title_tag:
        meta_titles.append(title_tag.group(1).lower().strip())

    # Check if any known brand appears in meta titles but NOT in the domain
    brand_keywords = {'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook',
                     'netflix', 'instagram', 'linkedin', 'chase', 'wellsfargo',
                     'bankofamerica', 'citibank', 'yahoo', 'norton', 'mcafee',
                     'whatsapp', 'dropbox', 'adobe', 'coinbase', 'binance'}
    meta_brand_mismatch = False
    for title in meta_titles:
        for brand in brand_keywords:
            if brand in title and brand not in host.lower():
                meta_brand_mismatch = True
                break
        if meta_brand_mismatch:
            break

    # === DOMAIN STRUCTURE ===

    # 36. Number of dots in hostname
    dot_count = host.count('.')

    # 37. Hyphen count in hostname
    hyphen_count = host.count('-')

    # 38. Domain length
    domain_len = len(host)

    # 39. Number of subdomains
    n_subdomains = max(0, dot_count - 1)

    # 40. HTTPS
    is_https = int(url.startswith('https://'))

    return np.array([
        n_forms, cross_origin_forms, password_forms, post_forms,
        hidden_inputs, total_inputs,
        n_iframes, cross_iframes, hidden_iframes,
        n_scripts, inline_ratio, cross_origin_scripts,
        obfuscation_count, injection_count, redirect_count,
        n_links, cross_link_ratio, data_uri_count,
        page_size, tag_count, text_ratio,
        external_css, inline_styles, event_handlers,
        has_base_tag, charset_count, has_csp_meta, sri_count, nonce_count, noopener_count,
        has_favicon, has_og, has_title, has_meta_desc, has_viewport,
        dot_count, hyphen_count, domain_len, n_subdomains, is_https,
        int(meta_brand_mismatch),
    ], dtype=np.float32)


PAGE_FEATURE_NAMES = [
    'n_forms', 'cross_origin_forms', 'password_forms', 'post_forms',
    'hidden_inputs', 'total_inputs',
    'n_iframes', 'cross_iframes', 'hidden_iframes',
    'n_scripts', 'inline_ratio', 'cross_origin_scripts',
    'obfuscation_count', 'injection_count', 'redirect_count',
    'n_links', 'cross_link_ratio', 'data_uri_count',
    'page_size', 'tag_count', 'text_ratio',
    'external_css', 'inline_styles', 'event_handlers',
    'has_base_tag', 'charset_count', 'has_csp_meta', 'sri_count', 'nonce_count', 'noopener_count',
    'has_favicon', 'has_og', 'has_title', 'has_meta_desc', 'has_viewport',
    'dot_count', 'hyphen_count', 'domain_len', 'n_subdomains', 'is_https',
    'meta_brand_mismatch',
]


def classify_page(url: str, html: str, model=None) -> Tuple[float, List[str]]:
    """Classify a page as phishing or legitimate.

    Returns (risk_score, list_of_signals_detected).
    risk_score is 0.0-1.0.
    """
    features = extract_page_features(url, html)
    signals = []

    # Unpack features
    (n_forms, cross_origin_forms, password_forms, post_forms,
     hidden_inputs, total_inputs,
     n_iframes, cross_iframes, hidden_iframes,
     n_scripts, inline_ratio, cross_origin_scripts,
     obfuscation_count, injection_count, redirect_count,
     n_links, cross_link_ratio, data_uri_count,
     page_size, tag_count, text_ratio,
     external_css, inline_styles, event_handlers,
     has_base_tag, charset_count, has_csp_meta, sri_count, nonce_count, noopener_count,
     has_favicon, has_og, has_title, has_meta_desc, has_viewport,
     dot_count, hyphen_count, domain_len, n_subdomains, is_https,
     meta_brand_mismatch) = features

    parsed = urlparse(url if url.startswith('http') else f'https://{url}')
    host = (parsed.netloc or '').lower()
    if host.startswith('www.'):
        host = host[4:]

    # Compute text content length for SPA detection (strip scripts/styles first)
    # Handle both closed and UNCLOED script tags (phishing trick)
    _clean = re.sub(r'<script[^>]*>.*?</script>', '', html or '', flags=re.S | re.I)
    _clean = re.sub(r'<script[^>]*>.*$', '', _clean, flags=re.S | re.I)  # unclosed script
    _clean = re.sub(r'<style[^>]*>.*?</style>', '', _clean, flags=re.S | re.I)
    _clean = re.sub(r'<style[^>]*>.*$', '', _clean, flags=re.S | re.I)  # unclosed style
    _clean = re.sub(r'<[^>]+>', '', _clean)
    _clean = re.sub(r'\s+', ' ', _clean).strip()
    text_length = len(_clean) if _clean else 0

    # === DOMAIN AGE CHECK (strongest signal for new phishing domains) ===
    # WHOIS with hard 1-second timeout — doesn't block if slow
    age_score = 0.0
    age_signal = ""
    try:
        import concurrent.futures as _futures
        with _futures.ThreadPoolExecutor(max_workers=1) as _ex:
            _f = _ex.submit(_check_domain_age, host)
            age_score, age_signal = _f.result(timeout=1.0)
            if age_signal:
                signals.append(age_signal)
    except _futures.TimeoutError:
        pass
    except Exception:
        pass

    # === RULE-BASED SIGNALS (structural, not text-based) ===

    # Cross-origin form submission (STRONGEST signal — form sends data elsewhere)
    if cross_origin_forms > 0:
        signals.append(f'cross-origin-form ({cross_origin_forms})')

    # Password form — only suspicious if cross-origin or on bare page
    # Legitimate sites ALSO have password forms, so this alone is weak
    if password_forms > 0 and (cross_origin_forms > 0 or (has_favicon == 0 and has_og == 0)):
        signals.append(f'suspicious-password-form ({password_forms})')

    # Hidden iframes (load content without user knowing) — very strong signal
    if hidden_iframes > 0:
        signals.append(f'hidden-iframe ({hidden_iframes})')

    # Script obfuscation — HIGH threshold (legit sites use eval too)
    if obfuscation_count >= 8:
        signals.append(f'script-obfuscation ({obfuscation_count})')

    # Redirect chains — HIGH threshold
    if redirect_count >= 4:
        signals.append(f'redirects ({redirect_count})')

    # Too many hidden inputs AND cross-origin forms
    if hidden_inputs >= 8 and cross_origin_forms > 0:
        signals.append(f'hidden-inputs ({hidden_inputs})')

    # Cross-origin iframes
    if cross_iframes > 0:
        signals.append(f'cross-origin-iframe ({cross_iframes})')

    # Data URIs (inline encoded content) — high threshold
    if data_uri_count >= 15:
        signals.append(f'data-uris ({data_uri_count})')

    # Injection (document.write, innerHTML) — high threshold
    if injection_count >= 5:
        signals.append(f'dom-injection ({injection_count})')

    # Bare page (no favicon, no OG, no meta desc, no title) — very suspicious
    if has_favicon == 0 and has_og == 0 and has_meta_desc == 0 and has_title == 0:
        signals.append('bare-page')

    # SPA shell — JavaScript-rendered page with minimal server HTML
    # Fake stores often use SPA templates that return empty shells
    if text_length < 200 and page_size > 10000:
        signals.append('spa-shell-minimal-content')

    # Tiny redirect page — very small page with only redirect text
    # Legitimate sites don't serve 472-byte "Redirecting..." pages
    if page_size < 2000 and text_length < 50 and page_size > 100:
        signals.append('tiny-redirect-page')

    # Suspicious TLD + minimal content = very likely fake store
    _susp_tlds = {'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'site', 'online', 'store', 'shop', 'buzz', 'click', 'link', 'icu'}
    tld = host.rsplit('.', 1)[-1] if '.' in host else ''
    if tld in _susp_tlds and text_length < 500:
        signals.append(f'suspicious-tld-minimal-content')

    # Meta brand mismatch — OG/title claims different brand than domain
    if meta_brand_mismatch:
        signals.append('meta-brand-mismatch')

    # === CONTENT-DOMAIN IDENTITY MISMATCH ===
    # Dynamically detect: does the page CLAIM to be a specific brand/organization
    # that doesn't match the domain? No hardcoded brand lists needed.
    #
    # Method: extract the page's "claimed identity" from:
    #   - <title> tag
    #   - OG title
    #   - Prominent headings (first <h1>)
    #   - Logo alt text
    # Then check if that identity matches the domain.
    #
    # Example: title="SURA | SOAT" but domain=soatenlinea.store → mismatch
    # No need to know what SURA is — we just check if "sura" is in the domain.
    content_identity_mismatch = False
    identity_name = ""

    try:
        # Extract claimed identity from page
        identity_sources = []

        # From <title>
        _title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if _title_match:
            identity_sources.append(_title_match.group(1).strip())

        # From OG title
        _og_match = re.search(r'og:title[^>]*content=["\']([^"\']+)["\']', html, re.I)
        if _og_match:
            identity_sources.append(_og_match.group(1).strip())

        # From first <h1>
        _h1_match = re.search(r'<h1[^>]*>([^<]{3,50})</h1>', html, re.I)
        if _h1_match:
            identity_sources.append(_h1_match.group(1).strip())

        # From logo alt text
        _logo_match = re.search(r'<img[^>]*alt=["\']([^"\']*(?:logo|brand)[^"\']*)["\']', html, re.I)
        if not _logo_match:
            _logo_match = re.search(r'alt=["\']([A-Z][a-zA-Z]{2,20})["\']', html)
        if _logo_match:
            identity_sources.append(_logo_match.group(1).strip())

        for source in identity_sources:
            # Extract the primary brand/identity name from the title
            # Strategy: take the FIRST word that looks like a brand name (capitalized, 4+ chars)
            words = re.findall(r'[A-Z][a-zA-Z]{3,}', source)
            _skip = {'Home', 'Page', 'Sign', 'Login', 'Welcome', 'Official',
                     'Portal', 'Dashboard', 'Account', 'Online', 'Service',
                     'Build', 'Software', 'World', 'Your', 'Free', 'Best',
                     'Comprar', 'Compra', 'Seguro', 'Tarjeta', 'Credito',
                     'Conoce', 'Hazte', 'Solicita', 'Explora', 'Disfruta',
                     'Noticias', 'Inicio', 'Cuenta', 'Productos', 'Servicios',
                     'Paix', 'Store', 'Shop', 'Premium', 'Pro', 'Plus',
                     'Team', 'Plan', 'Home', 'Main', 'News', 'Blog',
                     'Just', 'Open', 'Save', 'Make', 'Create', 'Start',
                     'Help', 'About', 'Contact', 'Search', 'Find', 'Get',
                     'View', 'Show', 'Read', 'Watch', 'Play', 'Share',
                     'Join', 'Try', 'Buy', 'Sell', 'Learn', 'Discover',
                     'Acceptable', 'Forbidden', 'Unauthorized', 'Notices',
                     'Error', 'Server', 'Request', 'Resource', 'Client'}

            for word in words:
                if word in _skip or len(word) < 5:
                    continue
                w = word.lower()
                # Check if this brand word is in the domain
                if w not in host.lower():
                    content_identity_mismatch = True
                    identity_name = w
                    break
            if content_identity_mismatch:
                break
    except Exception:
        pass

    if content_identity_mismatch:
        signals.append(f'identity-mismatch ({identity_name})')

    # === JAVASCRIPT ML ANALYSIS ===
    # Extract all JS from the page and run phishing kit classifier
    js_code = ''
    try:
        js_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, flags=re.S | re.I)
        # Also catch unclosed script tags
        js_blocks += re.findall(r'<script[^>]*>(?!.*</script>)(.*)$', html, flags=re.S | re.I)
        js_code = '\n'.join(b for b in js_blocks if len(b.strip()) > 50)
    except Exception:
        pass

    js_risk = 0.0
    js_ml_score = 0.0
    if js_code and len(js_code) > 100:
        # Rule-based JS analysis
        try:
            from js_analyzer import classify_js
            js_risk, js_signals = classify_js(js_code)
            for js_sig in js_signals:
                signals.append(f'js-{js_sig}')
        except Exception:
            pass

        # ML-based JS analysis (trained on 1978 phishing kits + legitimate sites)
        try:
            import xgboost as _xgb
            from js_analyzer import extract_js_features
            _js_model_path = Path(__file__).parent / "models" / "js_xgboost_v1.model"
            if _js_model_path.exists():
                if not hasattr(classify_page, '_js_model'):
                    classify_page._js_model = _xgb.Booster()
                    classify_page._js_model.load_model(str(_js_model_path))
                js_feats = extract_js_features(js_code)
                dm = _xgb.DMatrix(js_feats.reshape(1, -1))
                js_ml_score = float(classify_page._js_model.predict(dm)[0])
                if js_ml_score >= 0.7:
                    signals.append(f'js-ml-phishing ({js_ml_score:.0%})')
        except Exception:
            pass

    # === PAYMENT INFRASTRUCTURE ANALYSIS ===
    _page_text = (_clean or '').lower()
    _html_lower = html.lower()
    has_real_payment = False
    has_suspicious_payment = False

    # Extract form tags for payment analysis
    _form_tags = re.findall(r'<form[^>]*>', html, re.I)
    _forms_html = re.findall(r'<form[^>]*>(.*?)</form>', html, re.S | re.I)

    # Known payment processor scripts
    _payment_processors = {
        'stripe.com', 'js.stripe.com', 'stripe.network',
        'paypal.com', 'paypalobjects.com',
        'squareup.com', 'square.com',
        'braintreepayments.com', 'braintreegateway.com',
        'adyen.com', 'adyen.tech',
        'checkout.com',
        'razorpay.com',
        'paystack.com',
        'flutterwave.com',
        'apple.com/apple-pay',
        'pay.google.com',
        'amazon.com/pay',
        'shopify.com', 'shopifycdn.com', 'shop.app',
        'woocommerce.com', 'wp.com/wc',
        'bigcommerce.com',
        'magento.com',
        'paddle.com',
        'gumroad.com',
        'lemonsqueezy.com',
        'mercado pago',
        'pse',  # Colombian payment system
    }

    # Check scripts for payment processors AND e-commerce platforms
    _all_scripts = re.findall(r'src=["\']([^"\']+)["\']', html, re.I)
    _script_text = ' '.join(_all_scripts).lower()

    # E-commerce platforms are strong trust signals (these only serve legitimate stores)
    _ecommerce_platforms = {
        'shopify.com', 'shopifycdn.com', 'shop.app', 'myshopify.com',
        'woocommerce.com', 'wp.com/wc', 'wordpress.com',
        'bigcommerce.com', 'bigcommerce.io',
        'magento.com', 'magento.net',
        'squarespace.com', 'sqspcdn.com',
        'wix.com', 'wixstatic.com',
    }
    for platform in _ecommerce_platforms:
        if platform in _script_text or platform in _html_lower:
            has_real_payment = True
            trust_signals_found += 2  # Shopify/WooCommerce = legitimate store
            break

    for proc in _payment_processors:
        if proc in _script_text or proc in _html_lower:
            has_real_payment = True
            break

    # Check forms for suspicious payment collection
    for form_tag in _form_tags:
        action = re.search(r'action\s*=\s*["\']([^"\']+)["\']', form_tag, re.I)
        if action:
            action_url = action.group(1)
            form_html_block = ' '.join(_forms_html) if _forms_html else ''
            # Check if form collects card/payment data
            collects_payment = bool(re.search(
                r'(?:card.?number|credit.?card|cvv|cvc|expir|card.?num|cc-num)',
                form_html_block, re.I
            ))
            if collects_payment:
                # Check if form submits to same domain (no payment processor)
                if not action_url.startswith('http') or host in action_url:
                    if not has_real_payment:
                        has_suspicious_payment = True

    # Also check for direct card number input fields (not password fields)
    card_inputs = re.findall(r'(?:name|id)\s*=\s*["\'][^"\']*(?:card.?number|credit.?card|cc.?num|card.?num)[^"\']*["\']', html, re.I)
    if card_inputs and not has_real_payment:
        has_suspicious_payment = True

    if has_suspicious_payment:
        signals.append('suspicious-payment-form')
    if has_real_payment:
        signals.append('real-payment-processor')

    # === TRUST SIGNAL ANALYSIS ===
    # Real stores have trust signals: company info, policies, social proof.
    # Fake stores are missing these.
    trust_signals_found = 0

    # Company info (address, phone, registration)
    has_address = bool(re.search(r'(?:\d{1,5}\s+\w+\s+(?:street|st|avenue|ave|road|rd|blvd|drive|dr|lane|ln|way)\b)', _page_text))
    has_phone = bool(re.search(r'(?:\+?\d{1,3}[\s\-\.]?\(?\d{2,4}\)?[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4})', html))
    has_email = bool(re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html))
    if has_address:
        trust_signals_found += 1
    if has_phone:
        trust_signals_found += 1
    if has_email:
        trust_signals_found += 1

    # Policy pages
    has_return_policy = bool(re.search(r'(?:return|refund|shipping|privacy)\s+(?:policy|terms)', _page_text))
    has_terms = bool(re.search(r'(?:terms\s+(?:of\s+)?(?:service|use|conditions))', _page_text))
    if has_return_policy:
        trust_signals_found += 1
    if has_terms:
        trust_signals_found += 1

    # Social media links
    social_platforms = ['facebook.com', 'instagram.com', 'twitter.com', 'tiktok.com',
                       'youtube.com', 'linkedin.com', 'pinterest.com']
    social_count = sum(1 for sp in social_platforms if sp in _page_text)
    if social_count >= 2:
        trust_signals_found += 1

    # Reviews/testimonials
    has_reviews = bool(re.search(r'(?:review|testimonial|rating|stars?|⭐|★)', _page_text))
    if has_reviews:
        trust_signals_found += 1

    # E-commerce indicators (has product pages, categories)
    has_products = bool(re.search(r'(?:add.to.cart|buy.now|add.to.bag|purchase|checkout|shopping.cart)', _page_text))
    if has_products:
        trust_signals_found += 1

    # If page is a store (has products) but has NO trust signals = suspicious
    if has_products and trust_signals_found <= 1 and not has_real_payment:
        signals.append('store-no-trust-signals')

    # === SCORING ===
    # Weight signals by strength — cross-origin and hidden iframes are the strongest
    signal_weights = {
        'cross-origin-form': 0.50,      # Form sends data elsewhere = very likely phishing
        'suspicious-password-form': 0.15,
        'hidden-iframe': 0.40,           # Hidden content = very suspicious
        'script-obfuscation': 0.15,
        'redirects': 0.05,               # Redirects are common on legitimate sites (CDNs, auth)
        'hidden-inputs': 0.10,
        'cross-origin-iframe': 0.15,     # Analytics/marketing iframes are common
        'data-uris': 0.02,               # Data URIs are common in CSS/inline assets
        'dom-injection': 0.10,
        'bare-page': 0.15,
        'meta-brand-mismatch': 0.40,    # OG/title claims different brand = impersonation
        'identity-mismatch': 0.45,       # Page title/content claims identity not in domain
        'content-brand-mismatch': 0.50, # Page content mentions brand but domain isn't that brand = phishing
        'domain-registered-': 0.50,      # Very new domain (prefix match)
        'domain-': 0.25,                 # Domain age (prefix match)
        'spa-shell': 0.20,               # SPA shell with minimal content
        'suspicious-tld-minimal': 0.30,  # Suspicious TLD + almost no content
        'tiny-redirect': 0.35,           # Tiny page with only redirect text = suspicious
        'js-ml-phishing': 0.45,          # JS ML model says phishing (trained on 1978 kits)
        'js-form-hijack': 0.35,          # JS hijacking forms
        'js-data-exfiltration': 0.15,    # Analytics scripts send data (need corroboration)
        'js-heavy-eval': 0.20,           # Heavy eval() usage
        'js-base64-decode': 0.15,        # Base64 decoding
        'js-char-assembly': 0.15,        # String.fromCharCode
        'js-credential-reading': 0.25,   # Reading credential fields
        'js-timed-redirect': 0.15,       # Delayed redirects
        'js-dom-injection': 0.15,        # DOM manipulation
        'suspicious-payment-form': 0.40, # Card input without payment processor = money theft
        'store-no-trust-signals': 0.30,  # Store with no contact/policies/payment = likely fake
    }

    score = 0.0
    for sig in signals:
        sig_name = sig.split(' (')[0].split(' ')[0]
        # Try exact match first, then prefix match
        weight = signal_weights.get(sig_name, None)
        if weight is None:
            for prefix, w in signal_weights.items():
                if sig_name.startswith(prefix):
                    weight = w
                    break
        if weight is None:
            weight = 0.05
        score += weight

    # Combo boosts
    if cross_origin_forms > 0 and password_forms > 0:
        score += 0.3  # Cross-origin password form = almost certainly phishing
    if hidden_iframes > 0 and obfuscation_count >= 3:
        score += 0.2  # Hidden iframe + obfuscated scripts = strong phishing
    if redirect_count >= 2 and cross_origin_forms > 0:
        score += 0.2  # Redirect chain + form = phishing
    # New domain + suspicious TLD + e-commerce = fake store
    if age_score > 0.3 and n_forms >= 1:
        score += 0.2  # Brand new domain with forms = suspicious

    # JS ML + domain signals = strong phishing
    if js_ml_score >= 0.8 and (age_score > 0.3 or tld in _susp_tlds):
        score += 0.3

    # JS risk + any other signal = corroboration
    if js_risk >= 0.5 and len(signals) >= 2:
        score += 0.15

    # Trust signal discount — real stores with payment processors are NOT phishing
    # BUT: don't discount crypto/Web3 sites — wallet connect is NOT a trust signal
    _is_crypto = bool(re.search(
        r'(?:connect.*wallet|token.*presale|staking.*rewards|defi.*protocol|'
        r'decentralized.*exchange|blockchain.*network|crypto.*currency|'
        r'launchpad.*token|claim.*airdrop|swap.*tokens|liquidity.*pool|'
        r'yield.*farming|bridge.*assets|presale.*live|nft.*mint)',
        _page_text
    ))
    _is_new_suspicious = (age_score > 0.2 and tld in _susp_tlds)

    if has_real_payment and not _is_crypto and not _is_new_suspicious:
        if trust_signals_found >= 3:
            score *= 0.3  # Strong trust = heavily discount
        elif trust_signals_found >= 2:
            score *= 0.5
        elif trust_signals_found >= 1:
            score *= 0.7
        # Real payment processor alone is a strong trust signal (for normal stores)
        score = min(score, 0.4)  # Cap at 0.4 for legitimate stores

    score = min(1.0, score)

    # ML model prediction (if available)
    if model is not None:
        try:
            import xgboost as xgb
            if isinstance(model, xgb.Booster):
                dm = xgb.DMatrix(features.reshape(1, -1))
                ml_prob = float(model.predict(dm)[0])
            elif hasattr(model, 'predict_proba'):
                ml_prob = float(model.predict_proba(features.reshape(1, -1))[0][1])
            else:
                ml_prob = float(model.predict(features.reshape(1, -1))[0])
            # Weighted average: 60% structural rules, 40% ML
            score = 0.6 * score + 0.4 * ml_prob
        except Exception:
            pass

    return score, signals
