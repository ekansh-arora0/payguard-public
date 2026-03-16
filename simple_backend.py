
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import re
from datetime import datetime, timezone
import httpx

app = FastAPI(title="PayGuard Simple API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}

@app.get("/api/v1/health")
async def health_v1():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}

async def check_url_redirects(url: str) -> tuple[str, list[str]]:
    """Follow redirects and return final URL + redirect chain."""
    redirect_chain = [url]
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            resp = await client.get(url, headers={"User-Agent": "PayGuard/1.0"})
            final_url = str(resp.url)
            # Build redirect chain from history
            for redirect in resp.history:
                redirect_url = str(redirect.url)
                if redirect_url not in redirect_chain:
                    redirect_chain.append(redirect_url)
            if final_url not in redirect_chain:
                redirect_chain.append(final_url)
            return final_url, redirect_chain
    except Exception:
        return url, redirect_chain

@app.get("/api/v1/risk")
async def check_risk(url: str, fast: bool = False, follow_redirects: bool = True):
    """Check URL risk for phishing detection with enhanced patterns"""
    from urllib.parse import urlparse, unquote
    
    # Follow redirects if requested
    original_url = url
    redirect_chain = [url]
    if follow_redirects:
        try:
            url, redirect_chain = await check_url_redirects(url)
        except Exception:
            pass
    
    # Parse URL
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = unquote(parsed.path.lower())
    query = unquote(parsed.query.lower())
    
    # Remove port if present for domain checking
    domain_clean = domain.split(':')[0]
    
    # Safe domains whitelist (exact matches or major subdomains)
    safe_domains_exact = {
        'paypal.com', 'www.paypal.com', 'paypal.me',
        'amazon.com', 'www.amazon.com', 'smile.amazon.com',
        'google.com', 'www.google.com', 'accounts.google.com',
        'facebook.com', 'www.facebook.com',
        'apple.com', 'www.apple.com', 'icloud.com',
        'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
        'netflix.com', 'www.netflix.com',
        'chase.com', 'www.chase.com', 'secure.chase.com',
        'wellsfargo.com', 'www.wellsfargo.com',
        'bankofamerica.com', 'www.bankofamerica.com',
        'youtube.com', 'www.youtube.com',
        'twitter.com', 'x.com', 'www.twitter.com',
        'instagram.com', 'www.instagram.com',
        'linkedin.com', 'www.linkedin.com',
        'github.com', 'www.github.com',
        'reddit.com', 'www.reddit.com',
        'dropbox.com', 'www.dropbox.com',
        'spotify.com', 'www.spotify.com',
        'uber.com', 'www.uber.com',
        'airbnb.com', 'www.airbnb.com',
        # Educational
        'pearson.com', 'pearsoned.com', 'k12.com', 'fcps.edu',
        'canvas.instructure.com', 'blackboard.com', 'moodle.org',
        'mhc.edu', 'edu',
        # Common platforms
        'opencode.ai', 'vercel.app', 'netlify.app', 'cloudflare.com',
        'shopify.com', 'stripe.com', 'zoom.us', 'dropbox.com',
        'slack.com', 'teams.microsoft.com', 'discord.com',
    }
    
    # Check exact domain match first
    if domain_clean in safe_domains_exact:
        return {
            "url": url,
            "domain": domain,
            "risk_score": 0,
            "risk_level": "LOW",
            "risk_factors": [],
            "checks_performed": ["domain_whitelist"],
            "response_time_ms": 5
        }
    
    # Check for known safe subdomains
    for safe in safe_domains_exact:
        if domain_clean.endswith('.' + safe) or domain_clean == safe:
            return {
                "url": url,
                "domain": domain,
                "risk_score": 0,
                "risk_level": "LOW",
                "risk_factors": [],
                "checks_performed": ["domain_whitelist"],
                "response_time_ms": 5
            }
    
    # Initialize risk tracking
    risk_score = 0
    risk_factors = []
    checks_performed = ["domain_whitelist"]
    
    # Report redirect chain if redirects were followed
    if follow_redirects and len(redirect_chain) > 1:
        risk_factors.append({"code": "redirect_chain", "description": f"🔗 Redirect chain detected ({len(redirect_chain)} hops: {' -> '.join([u[:30] + '...' if len(u) > 30 else u for u in redirect_chain])}", "weight": 10})
    
    # ===== 1. TYPOSQUATTING DETECTION =====
    typosquatting_patterns = [
        # PayPal variations
        (r'paypa[1l][^l]|payp[4a]l|pay-pal|paypa1|p[4a]ypal', 95, "paypal_typo", "PayPal typo-squatting"),
        
        # Amazon variations  
        (r'ama[sz][o0]n|amaz[o0]n|arnazon|amazon-\w+|amaz0n', 90, "amazon_typo", "Amazon typo-squatting"),
        
        # Apple variations
        (r'app1e|appl[e3]|icloud-\w+|apple-\w{3,}', 90, "apple_typo", "Apple typo-squatting"),
        
        # Google variations
        (r'g[o0]{2,}gle|g[o0]{2,}g1e|gogle|google-\w{4,}', 90, "google_typo", "Google typo-squatting"),
        
        # Microsoft variations
        (r'micr[o0]{1,}s[o0]ft|micros[o0]ft|micro-soft|microsoft-\w{3,}', 90, "microsoft_typo", "Microsoft typo-squatting"),
        
        # Facebook variations
        (r'faceb[o0]{2,}k|faceb[o0]{2,}k|facebook-\w{4,}', 90, "facebook_typo", "Facebook typo-squatting"),
        
        # Netflix variations
        (r'netf1ix|netfl[ix1]|netflix-\w{4,}', 85, "netflix_typo", "Netflix typo-squatting"),
        
        # Banking variations
        (r'ch[a4]se|chase-\w{3,}|wellsfarg[o0]|bankofameric[a4]', 95, "bank_typo", "Bank typo-squatting"),
        (r'citib[a4]nk|b[o0][a4]|usb[a4]nk|pncb[a4]nk', 95, "bank_typo", "Bank typo-squatting"),
        
        # Social media
        (r'twitt[e3]r|tw1tter|twitter-\w{3,}|inst[a4]gr[a4]m', 85, "social_typo", "Social media typo-squatting"),
        
        # Shopping
        (r'eb[a4]y|shop1fy|etsy-|ebay-\w{3,}', 85, "shopping_typo", "Shopping site typo-squatting"),
        
        # Crypto/Finance
        (r'c[o0]inb[a4]se|bin[a4]nce|kr[a4]ken|blockch[a4]in', 95, "crypto_typo", "Crypto exchange typo-squatting"),
    ]
    
    for pattern, weight, code, description in typosquatting_patterns:
        if re.search(pattern, domain_clean):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # ===== 2. SUSPICIOUS TLDs =====
    suspicious_tlds = [
        (r'\.(tk|ml|ga|cf|gq|top|xyz|work|date|click|link|zip)$', 40, "suspicious_tld", "Suspicious/free TLD"),
        (r'\.(country|download|gdn|men|science|work)$', 50, "highrisk_tld", "High-risk TLD"),
    ]
    
    for pattern, weight, code, description in suspicious_tlds:
        if re.search(pattern, domain_clean):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # ===== 3. DOMAIN STRUCTURE ANALYSIS =====
    
    # IP address instead of domain
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_clean):
        risk_score += 90
        risk_factors.append({"code": "ip_address", "description": "IP address instead of domain name", "weight": 90})
    
    # Excessive subdomains (likely suspicious)
    subdomain_count = domain_clean.count('.')
    if subdomain_count >= 4:
        risk_score += 40
        risk_factors.append({"code": "many_subdomains", "description": f"Excessive subdomains ({subdomain_count+1} levels)", "weight": 40})
    elif subdomain_count >= 3:
        risk_score += 20
        risk_factors.append({"code": "multiple_subdomains", "description": f"Multiple subdomains ({subdomain_count+1} levels)", "weight": 20})
    
    # Brand name in subdomain of suspicious domain (e.g., paypal.suspicious-site.com)
    brand_in_subdomain = [
        (r'paypal\.', 85, "paypal_subdomain", "PayPal in subdomain"),
        (r'amazon\.', 80, "amazon_subdomain", "Amazon in subdomain"),
        (r'google\.', 80, "google_subdomain", "Google in subdomain"),
        (r'apple\.', 80, "apple_subdomain", "Apple in subdomain"),
        (r'microsoft\.', 80, "microsoft_subdomain", "Microsoft in subdomain"),
        (r'facebook\.', 80, "facebook_subdomain", "Facebook in subdomain"),
        (r'netflix\.', 80, "netflix_subdomain", "Netflix in subdomain"),
        (r'chase\.', 90, "chase_subdomain", "Chase in subdomain"),
        (r'bankofamerica\.', 90, "boa_subdomain", "Bank of America in subdomain"),
        (r'wellsfargo\.', 90, "wellsfargo_subdomain", "Wells Fargo in subdomain"),
    ]
    
    for pattern, weight, code, description in brand_in_subdomain:
        if re.search(pattern, domain_clean):
            # Check it's not a legitimate subdomain of the brand's own domain
            if not any(domain_clean.endswith('.' + brand) or domain_clean == brand 
                      for brand in ['paypal.com', 'amazon.com', 'google.com', 'apple.com', 
                                   'microsoft.com', 'facebook.com', 'netflix.com', 'chase.com']):
                risk_score += weight
                risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # Suspicious redirect parameters (JavaScript redirect tracking)
    redirect_tracking_params = [
        (r'[?&](ch|js|sid|session|token)=[a-zA-Z0-9_-]{10,}', 35, "redirect_tracking", "Redirect tracking parameters (common in scam chains)"),
        (r'[?&](redirect|url|to|goto|target)=https?://', 40, "external_redirect", "External redirect parameter"),
    ]
    
    for pattern, weight, code, description in redirect_tracking_params:
        if re.search(pattern, query):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # ===== 4. URL PATH ANALYSIS =====
    
    # Credential harvesting paths - must be exact path segments, not partial matches
    # Split path by / to get individual segments for exact matching
    path_segments = [seg.lower() for seg in path.split('/') if seg]
    
    credential_patterns = [
        # (exact_segment_match, weight, code, description)
        ('login', 25, "login_path", "Login path on suspicious domain"),
        ('signin', 25, "login_path", "Login path on suspicious domain"),
        ('sign-in', 25, "login_path", "Login path on suspicious domain"),
        ('log-in', 25, "login_path", "Login path on suspicious domain"),
        ('authenticate', 25, "login_path", "Login path on suspicious domain"),
        ('verify', 30, "verify_path", "Verification path on suspicious domain"),
        ('verification', 30, "verify_path", "Verification path on suspicious domain"),
        ('confirm', 30, "verify_path", "Verification path on suspicious domain"),
        ('validation', 30, "verify_path", "Verification path on suspicious domain"),
        ('account', 25, "account_path", "Account-related path"),
        ('password', 25, "account_path", "Account-related path"),
        ('reset', 25, "account_path", "Account-related path"),
        ('recover', 25, "account_path", "Account-related path"),
        ('update', 25, "update_path", "Account update path"),
        ('upgrade', 25, "update_path", "Account update path"),
        ('secure', 25, "update_path", "Account update path"),
        ('locked', 25, "update_path", "Account update path"),
        ('billing', 25, "payment_path", "Payment-related path"),
        ('payment', 25, "payment_path", "Payment-related path"),
        ('invoice', 25, "payment_path", "Payment-related path"),
        ('receipt', 25, "payment_path", "Payment-related path"),
    ]
    
    for segment, weight, code, description in credential_patterns:
        if segment in path_segments:
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # Suspicious query parameters
    suspicious_params = [
        (r'[?&](token|session|auth|key)=', 30, "suspicious_token", "Suspicious token parameter"),
        (r'(redirect|url|return|next)=https?://', 35, "open_redirect", "Open redirect parameter"),
        (r'(redirect|url|return|next)=/', 25, "redirect_param", "Redirect parameter"),
        (r'[?&](cmd|exec|run|ping|query)=', 40, "command_param", "Potential command injection"),
        (r'[?&](user|username|email|password)=', 25, "credential_param", "Credentials in URL"),
    ]
    
    for pattern, weight, code, description in suspicious_params:
        if re.search(pattern, query):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # ===== 5. ENCODING & OBFUSCATION =====
    
    # Punycode/homograph attacks
    if 'xn--' in domain_clean:
        risk_score += 80
        risk_factors.append({"code": "punycode", "description": "Punycode domain (possible homograph attack)", "weight": 80})
    
    # Mixed scripts (homograph attacks) - Cyrillic, Greek, etc.
    mixed_scripts = [
        (r'[\u0430-\u044f]', 95, "cyrillic_chars", "Cyrillic characters (homograph attack)"),
        (r'[\u03b1-\u03c9]', 95, "greek_chars", "Greek characters (homograph attack)"),
        (r'[\u0430]', 95, "cyrillic_a", "Cyrillic 'а' looks like Latin 'a'"),
        (r'[\u043e]', 95, "cyrillic_o", "Cyrillic 'о' looks like Latin 'o'"),
        (r'[\u0440]', 95, "cyrillic_p", "Cyrillic 'р' looks like Latin 'p'"),
    ]
    
    for pattern, weight, code, description in mixed_scripts:
        if re.search(pattern, domain_clean):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # Hex/obfuscated URLs
    if re.search(r'%[0-9a-f]{2}', url) and len(re.findall(r'%[0-9a-f]{2}', url)) > 3:
        risk_score += 25
        risk_factors.append({"code": "url_encoded", "description": "Heavily URL-encoded (obfuscation)", "weight": 25})
    
    # ===== 6. URL SHORTENERS & REDIRECTS =====
    
    url_shorteners = [
        (r'^(bit\.ly|tinyurl|t\.co|ow\.ly|buff\.ly|goo\.gl|short\.link|is\.gd|cli\.gs)', 60, "url_shortener", "URL shortener (hides destination)"),
    ]
    
    for pattern, weight, code, description in url_shorteners:
        if re.search(pattern, domain_clean):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # ===== 7. SUSPICIOUS PORTS =====
    
    if ':' in domain:
        port = domain.split(':')[-1]
        if port not in ['80', '443', '8080', '8443']:
            risk_score += 35
            risk_factors.append({"code": "unusual_port", "description": f"Unusual port: {port}", "weight": 35})
    
    # ===== 8. DIGITAL WALLET & CRYPTO SCAMS =====
    
    crypto_scams = [
        (r'(wallet|crypto|bitcoin|ethereum|nft)[\.-]?(connect|verify|sync|restore|claim)', 90, "crypto_scam", "Crypto wallet scam"),
        (r'metamask|metam[a4]sk|meta-mas[k1]|metamask-\w+', 95, "metamask_typo", "MetaMask typo-squatting"),
        (r'trustwallet|trust-walllet|trust[\.-]?wallet', 90, "trustwallet_typo", "Trust Wallet typo-squatting"),
        (r'coinbase|coinb[a4]se|coin-base|coinbase-\w+', 95, "coinbase_typo", "Coinbase typo-squatting"),
        (r'binance|bin[a4]nce|binance-\w+', 95, "binance_typo", "Binance typo-squatting"),
        (r'kraken|kr[a4]ken|kraken-\w+', 90, "kraken_typo", "Kraken typo-squatting"),
    ]
    
    for pattern, weight, code, description in crypto_scams:
        if re.search(pattern, domain_clean + path):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # ===== 9. URGENCY & SCAM KEYWORDS =====
    
    scam_keywords = [
        (r'(urgent|immediate|act.?now|limited.?time)', 20, "urgency", "Urgency keywords"),
        (r'(suspended|blocked|locked|restricted|unusual.?activity)', 25, "account_threat", "Account threat keywords"),
        (r'(verify|confirm|update|validate).{0,20}(account|identity|information)', 25, "verify_request", "Verification request"),
        (r'(prize|winner|congratulations|won|selected)', 20, "lottery_scam", "Lottery/prize scam"),
        (r'(refund|rebate|overcharge|billing.issue)', 20, "refund_scam", "Refund scam"),
        (r'(free|gift|bonus|reward).{0,10}(claim|click|get)', 20, "free_scam", "Free gift scam"),
    ]
    
    for pattern, weight, code, description in scam_keywords:
        if re.search(pattern, domain_clean + path + query):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # ===== 10. TECH SUPPORT SCAMS =====
    
    tech_support_scams = [
        (r'(support|help|tech|technical).{0,10}(microsoft|apple|windows|mac)', 80, "tech_support", "Fake tech support"),
        (r'virus|malware|infected|security.?alert|warning', 30, "virus_warning", "Virus/malware warning"),
        (r'call.?(now|immediately)?\s*\d{3}-?\d{3}-?\d{4}', 85, "phone_scam", "Phone number in URL"),
        (r'1-?800-?\d{3}-?\d{4}|1-?888-?\d{3}-?\d{4}', 70, "toll_free_scam", "Toll-free number in URL"),
    ]
    
    for pattern, weight, code, description in tech_support_scams:
        if re.search(pattern, domain_clean + path + query):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # ===== 11. DOMAIN AGE INDICATORS (simulated) =====
    # In production, you'd check WHOIS data
    
    # Very long domain names (often auto-generated)
    if len(domain_clean) > 40:
        risk_score += 15
        risk_factors.append({"code": "long_domain", "description": f"Very long domain ({len(domain_clean)} chars)", "weight": 15})
    
    # Auto-generated/random-looking domain names (high confidence indicators only)
    # Only flag if domain has multiple suspicious characteristics
    random_indicators = 0
    
    # Pattern 1: All consonants or all vowels (not normal words)
    if re.search(r'^[bcdfghjklmnpqrstvwxyz]{6,}$', domain_clean.split('.')[0]):
        random_indicators += 1
    
    # Pattern 2: Excessive numbers in domain
    digit_count = len(re.findall(r'\d', domain_clean))
    if digit_count >= 4:
        random_indicators += 1
    
    # Pattern 3: High entropy/random-looking (mixed case + numbers + special)
    main_domain = domain_clean.split('.')[0]
    if len(main_domain) >= 15 and len(set(main_domain)) >= 12:
        # High character variety suggests random generation
        random_indicators += 1
    
    # Only flag as random if multiple indicators present
    if random_indicators >= 2:
        risk_score += 25
        risk_factors.append({"code": "random_domain", "description": "Auto-generated domain name", "weight": 25})
    
    # Landing page / tracker domains
    landing_patterns = [
        (r'\b(lander|landers|landing|landings)\b', "landing_page", "Landing page domain"),
        (r'\b(track|tracker|trck|trk|tracking)\b', "tracker_domain", "Tracking domain"),
        (r'\b(click|clck|clk)\b', "click_tracker", "Click tracking domain"),
    ]
    for pattern, code, description in landing_patterns:
        if re.search(pattern, domain_clean):
            risk_score += 30
            risk_factors.append({"code": code, "description": description, "weight": 30})
    
    # Also check for tracker misspellings in query parameters
    if 'trck' in query or 'trk' in query:
        risk_score += 25
        risk_factors.append({"code": "tracker_param", "description": "Tracking domain in query parameters", "weight": 25})
    
    # Auto-generated random path segments (like weqdfewdfewdf123123)
    random_path_segments = 0
    for segment in path_segments:
        # Segment is 15+ chars with mix of letters and numbers (auto-generated)
        if len(segment) >= 15 and re.search(r'[a-z]', segment) and re.search(r'\d', segment):
            if len(set(segment)) >= 10:  # High variety = random
                random_path_segments += 1
    
    if random_path_segments >= 2:
        risk_score += 35
        risk_factors.append({"code": "random_paths", "description": f"Auto-generated path segments ({random_path_segments} found)", "weight": 35})
    elif random_path_segments == 1:
        risk_score += 15
        risk_factors.append({"code": "suspicious_path", "description": "Suspicious auto-generated path segment", "weight": 15})
    
    # Multiple tracking parameters (indicates tracking/redirect chain)
    # Add leading ? to query for regex matching
    query_for_regex = '?' + query
    tracking_params = re.findall(r'[?&](clickid|bcid|cid|zxcv|token|session|ref|source|utm_[a-z]+)=', query_for_regex)
    if len(tracking_params) >= 2:
        risk_score += 30
        risk_factors.append({"code": "heavy_tracking", "description": f"Heavy tracking parameters ({len(tracking_params)} found)", "weight": 30})
    
    # ===== CAP & DEDUPLICATE =====
    
    # Remove duplicate risk factors
    seen_codes = set()
    unique_factors = []
    for factor in risk_factors:
        if factor['code'] not in seen_codes:
            seen_codes.add(factor['code'])
            unique_factors.append(factor)
    risk_factors = unique_factors
    
    # Cap at 100
    risk_score = min(risk_score, 100)
    
    # ===== DETERMINE RISK LEVEL =====
    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    elif risk_score >= 10:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"
    
    checks_performed.extend(["typosquatting", "tld_analysis", "structure", "path_analysis", 
                            "encoding", "shorteners", "crypto_scams", "keyword_analysis"])
    
    return {
        "url": url,
        "domain": domain,
        "path": path,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "checks_performed": checks_performed,
        "detection_count": len(risk_factors),
        "response_time_ms": 20
    }

@app.post("/api/v1/risk")
async def check_risk_post(payload: dict):
    """Check URL risk via POST request (for menubar app compatibility)"""
    url = payload.get("url", "")
    fast = payload.get("fast", False)
    follow_redirects_flag = payload.get("follow_redirects", True)
    overlay_text = payload.get("overlay_text", "")
    
    # ========== OVERLAY TEXT SCAM DETECTION ==========
    # If overlay_text is provided, analyze it for scam patterns first
    if overlay_text:
        try:
            # Import the text scam analyzer
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from backend.risk_engine import RiskScoringEngine
            
            engine = RiskScoringEngine(None)
            scam_result = engine._analyze_text_for_scam(overlay_text)
            
            if scam_result and scam_result.get("is_scam"):
                conf = int(scam_result.get("confidence", 0))
                return {
                    "url": url or "overlay://text",
                    "domain": "overlay_text",
                    "risk_score": 100,
                    "risk_level": "HIGH",
                    "risk_factors": [f"Scam popup detected ({conf}% confidence)"],
                    "trust_score": max(0, 100 - conf),
                    "checks_performed": ["overlay_text_analysis"],
                    "scam_alert": {
                        "is_scam": True,
                        "confidence": conf,
                        "detected_patterns": scam_result.get("detected_patterns", []),
                        "senior_message": scam_result.get("senior_message", "STOP! This is a SCAM."),
                        "action_advice": scam_result.get("action_advice", "Close this window immediately.")
                    },
                    "response_time_ms": 5
                }
        except Exception as e:
            # Fall through to URL analysis if overlay detection fails
            pass
    
    # Follow redirects if requested
    original_url = url
    redirect_chain = [url]
    redirect_factors = []
    
    if follow_redirects_flag:
        try:
            url, redirect_chain = await check_url_redirects(url)
            if len(redirect_chain) > 1:
                redirect_factors.append({"code": "redirect_chain", "description": f"🔗 Redirect chain detected ({len(redirect_chain)} hops)", "weight": 15})
        except Exception:
            pass
    
    # Call the same logic as GET endpoint
    from urllib.parse import urlparse, unquote
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = unquote(parsed.path.lower())
    query = unquote(parsed.query.lower())
    domain_clean = domain.split(':')[0]
    
    # Safe domains whitelist
    safe_domains_exact = {
        'paypal.com', 'www.paypal.com', 'paypal.me',
        'amazon.com', 'www.amazon.com', 'smile.amazon.com',
        'google.com', 'www.google.com', 'accounts.google.com',
        'facebook.com', 'www.facebook.com',
        'apple.com', 'www.apple.com', 'icloud.com',
        'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
        'netflix.com', 'www.netflix.com',
        'chase.com', 'www.chase.com', 'secure.chase.com',
        'wellsfargo.com', 'www.wellsfargo.com',
        'bankofamerica.com', 'www.bankofamerica.com',
        'youtube.com', 'www.youtube.com',
        'twitter.com', 'x.com', 'www.twitter.com',
        'instagram.com', 'www.instagram.com',
        'linkedin.com', 'www.linkedin.com',
        'github.com', 'www.github.com',
        'reddit.com', 'www.reddit.com',
        'dropbox.com', 'www.dropbox.com',
        'spotify.com', 'www.spotify.com',
        'uber.com', 'www.uber.com',
        'airbnb.com', 'www.airbnb.com',
        # Educational
        'pearson.com', 'pearsoned.com', 'k12.com', 'fcps.edu',
        'canvas.instructure.com', 'blackboard.com', 'moodle.org',
        # Common platforms
        'opencode.ai', 'vercel.app', 'netlify.app', 'cloudflare.com',
        'shopify.com', 'stripe.com', 'zoom.us',
        'slack.com', 'teams.microsoft.com', 'discord.com',
    }
    
    if domain_clean in safe_domains_exact:
        return {
            "url": url,
            "domain": domain,
            "risk_score": 0,
            "risk_level": "LOW",
            "risk_factors": [],
            "trust_score": 100,
            "checks_performed": ["domain_whitelist"],
            "response_time_ms": 5
        }
    
    for safe in safe_domains_exact:
        if domain_clean.endswith('.' + safe) or domain_clean == safe:
            return {
                "url": url,
                "domain": domain,
                "risk_score": 0,
                "risk_level": "LOW",
                "risk_factors": [],
                "trust_score": 100,
                "checks_performed": ["domain_whitelist"],
                "response_time_ms": 5
            }
    
    # Initialize risk tracking
    risk_score = 0
    risk_factors = []
    
    # Parse path into segments for pattern matching
    path_segments = [seg.lower() for seg in path.split('/') if seg]
    
    # Pattern 1: Random-looking subdomains (auto-generated scam domains)
    subdomain_parts = domain_clean.split('.')
    for part in subdomain_parts[:-2]:  # Check subdomains, not TLD
        # Check for long random strings (mix of letters and numbers, 10+ chars) - HIGH risk
        if len(part) >= 10 and re.search(r'[a-z].*[0-9]|[0-9].*[a-z]', part):
            risk_score += 50
            risk_factors.append({"code": "random_subdomain", "description": f"Random-looking subdomain: {part[:20]}...", "weight": 50})
            break
        # Check for shorter random strings (5-9 chars) - MEDIUM risk
        elif len(part) >= 5 and re.search(r'[a-z].*[0-9]|[0-9].*[a-z]', part):
            risk_score += 25
            risk_factors.append({"code": "suspicious_subdomain", "description": f"Suspicious subdomain pattern: {part}", "weight": 25})
            break
    
    # Pattern 1b: Random-looking main domain names (like caish-djc, achel-xof)
    # Check if main domain (before TLD) looks auto-generated with hyphens and random chars
    if len(subdomain_parts) >= 2:
        main_domain = subdomain_parts[-2]  # e.g., "caish-djc" from "caish-djc.com"
        # Check for hyphenated random domains: caish-djc, bef25-sayasdf patterns
        if '-' in main_domain and len(main_domain) >= 8:
            parts = main_domain.split('-')
            # Check if parts look random (short, mixed alphanumeric)
            random_parts = [p for p in parts if len(p) >= 4 and (re.search(r'[0-9]', p) or len(p) <= 6)]
            if len(random_parts) >= 2 or (len(random_parts) == 1 and len(parts) == 2):
                risk_score += 30
                risk_factors.append({"code": "random_domain", "description": f"Auto-generated domain name: {main_domain}", "weight": 30})
    
    # Pattern 1c: Landing page / tracker domains
    landing_patterns = [
        (r'\b(lander|landers|landing|landings)\b', "landing_page", "Landing page domain"),
        (r'\b(track|tracker|trck|trk|tracking)\b', "tracker_domain", "Tracking domain"),
        (r'\b(click|clck|clk)\b', "click_tracker", "Click tracking domain"),
    ]
    for pattern, code, description in landing_patterns:
        if re.search(pattern, domain_clean):
            risk_score += 30
            risk_factors.append({"code": code, "description": description, "weight": 30})
    
    # Pattern 2: Suspicious redirect paths - must be exact path segments
    redirect_segments = ['zclkredirect', 'clkredirect', 'redirect', 'rd', 'jump', 'goto', 'out', 'exit']
    for redirect_seg in redirect_segments:
        if redirect_seg in path_segments:
            risk_score += 35
            risk_factors.append({"code": "redirect_path", "description": f"Redirect path detected: /{redirect_seg}", "weight": 35})
            break
    
    # Pattern 3: Tracking parameters (click IDs, visit IDs, session tracking)
    tracking_params = re.findall(r'(cid|clickid|extclickid|visitid|s|u|d|k|dtcbu|tsid|cs_fpid|cj)=[a-zA-Z0-9_-]{8,}', query)
    if len(tracking_params) >= 3:
        risk_score += 35
        risk_factors.append({"code": "heavy_tracking", "description": f"Heavy tracking parameters ({len(tracking_params)} found)", "weight": 35})
    elif len(tracking_params) >= 1:
        risk_score += 15
        risk_factors.append({"code": "tracking_params", "description": f"Tracking parameters detected", "weight": 15})
    
    # Pattern 4: Suspicious country-code TLDs often used for scams
    # .co.in (India commercial), .xyz, .top, .click, .link
    if re.search(r'\.(co\.in|xyz|top|click|link|date|gdn|men|science|country|download)$', domain_clean):
        risk_score += 35
        risk_factors.append({"code": "suspicious_tld", "description": "High-risk TLD commonly used for scams", "weight": 35})
    
    # Pattern 5: Typosquatting (brand impersonation with subtle changes)
    typosquatting_patterns = [
        (r'paypa[l1][^l]|payp[a4]l|p[a4]ypal|pay-pal', 90, "paypal_typo", "PayPal typo-squatting"),
        (r'ama[z2][o0]n|amaz[o0]n|amaz[o0]-|arnazon', 85, "amazon_typo", "Amazon typo-squatting"),
        (r'metam[a4]sk|metamask-|meta-mas[k1]', 90, "metamask_typo", "MetaMask typo-squatting"),
        (r'c[o0]inb[a4]se|coinb[a4]se|coin-base', 90, "coinbase_typo", "Coinbase typo-squatting"),
        (r'g[o0]{2,}gle|g[o0]{2}gle|g[o0]gle-', 85, "google_typo", "Google typo-squatting"),
        (r'app1e|appl[e3]|icloud-|apple-', 85, "apple_typo", "Apple typo-squatting"),
        (r'faceb[o0]{2,}k|faceb[o0]k|facebook-', 85, "facebook_typo", "Facebook typo-squatting"),
        (r'netf1ix|netfl[ix1]|netflix-', 80, "netflix_typo", "Netflix typo-squatting"),
    ]
    
    for pattern, weight, code, description in typosquatting_patterns:
        if re.search(pattern, domain_clean):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # Pattern 6: Redirect chain indicators
    # Look for redirect patterns in query parameters
    redirect_params = re.findall(r'(redirect|url|return|next|to|target|destination|ch|js)=', query)
    if len(redirect_params) >= 2:
        risk_score += 35
        risk_factors.append({"code": "redirect_chain", "description": f"Multiple redirect parameters detected ({len(redirect_params)})", "weight": 35})
    
    # Pattern 7: Free TLDs (.tk, .ml, .ga, .cf, .gq)
    if re.search(r'\.(tk|ml|ga|cf|gq)$', domain_clean):
        risk_score += 45
        risk_factors.append({"code": "free_tld", "description": "Free domain TLD commonly abused by scammers", "weight": 45})
    
    # Pattern 8: IP addresses instead of domains
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_clean):
        risk_score += 85
        risk_factors.append({"code": "ip_address", "description": "Uses IP address instead of domain name", "weight": 85})
    
    # Pattern 9: URL shorteners that hide destination
    if re.search(r'^(bit\.ly|tinyurl|t\.co|ow\.ly|buff\.ly|is\.gd|cli\.gs|short\.link)', domain_clean):
        risk_score += 50
        risk_factors.append({"code": "url_shortener", "description": "URL shortener hides final destination", "weight": 50})
    
    # Pattern 10: Excessive subdomains (more than 3 levels)
    if len(subdomain_parts) > 4:
        risk_score += 25
        risk_factors.append({"code": "many_subdomains", "description": f"Excessive subdomains ({len(subdomain_parts)} levels)", "weight": 25})
    
    # Pattern 11: Credential harvesting paths - exact segment matching only
    path_segments = [seg.lower() for seg in path.split('/') if seg]
    credential_segments = ['login', 'signin', 'verify', 'confirm', 'account', 'password', 'secure']
    for cred_segment in credential_segments:
        if cred_segment in path_segments:
            risk_score += 20
            risk_factors.append({"code": "credential_path", "description": f"Credential harvesting path detected: /{cred_segment}", "weight": 20})
            break
    
    # Pattern 12: Crypto/Wallet scams
    crypto_patterns = [
        (r'wallet.*connect|wallet.*sync|wallet.*verify', 80, "wallet_scam", "Fake wallet connection"),
        (r'crypto.*claim|crypto.*verify|crypto.*restore', 75, "crypto_scam", "Crypto scam pattern"),
        (r'trust.*wallet|trustwallet', 80, "trustwallet_scam", "TrustWallet scam"),
        (r'binance|binance-.*|binance.*verify', 85, "binance_typo", "Binance impersonation"),
    ]
    
    for pattern, weight, code, description in crypto_patterns:
        if re.search(pattern, domain_clean + path):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # Pattern 12b: Redirect tracking parameters (common in scam chains)
    redirect_tracking_params = [
        (r'[?&](ch|js|sid|session|token)=[a-zA-Z0-9_-]{10,}', 35, "redirect_tracking", "Redirect tracking parameters (common in scam chains)"),
        (r'[?&](redirect|url|to|goto|target)=https?://', 40, "external_redirect", "External redirect parameter"),
    ]
    
    for pattern, weight, code, description in redirect_tracking_params:
        if re.search(pattern, query):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # Pattern 13: Suspicious keywords in domain
    scam_keywords = [
        (r'(urgent|immediate|act.?now|limited.?time|expires?.?soon)', 25, "urgency", "Urgency keywords"),
        (r'(prize|winner|won|selected|congratulations|free.*gift)', 25, "lottery", "Lottery/prize scam"),
        (r'(verify|confirm|update|secure).{0,20}(account|identity)', 25, "verify", "Verification request"),
        (r'((suspended|blocked|restricted).{0,15}(account|access))', 30, "suspended", "Account threat"),
    ]
    
    for pattern, weight, code, description in scam_keywords:
        if re.search(pattern, domain_clean + path + query):
            risk_score += weight
            risk_factors.append({"code": code, "description": description, "weight": weight})
    
    # Remove duplicate risk factors
    seen_codes = set()
    unique_factors = []
    for factor in risk_factors:
        if factor['code'] not in seen_codes:
            seen_codes.add(factor['code'])
            unique_factors.append(factor)
    risk_factors = unique_factors
    
    # Cap at 100
    risk_score = min(risk_score, 100)
    
    # Determine risk level - BE MORE AGGRESSIVE
    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    elif risk_score >= 5:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"
    
    return {
        "url": url,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "trust_score": max(0, 100 - risk_score),
        "checks_performed": ["comprehensive_check"],
        "response_time_ms": 15
    }

@app.post("/api/media-risk/bytes")
async def analyze_media(payload: dict):
    """Simple scam detection"""
    content = payload.get("content", "")
    
    # Simple text analysis
    scam_patterns = [
        (r'\b1-\d{3}-\d{3}-\d{4}\b', 30, "phone_number"),
        (r'(?i)\b(urgent|immediate|act now)\b', 20, "urgency"),
        (r'(?i)\b(virus|infected|malware)\b', 25, "virus_warning"),
        (r'(?i)\b(suspended|blocked|expired)\b', 15, "account_threat"),
        (r'(?i)do not (close|restart)', 25, "do_not_close"),
    ]
    
    confidence = 0
    detected_patterns = []
    
    # Decode base64 and analyze (simplified)
    try:
        import base64
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        
        for pattern, weight, name in scam_patterns:
            if re.search(pattern, decoded):
                confidence += weight
                detected_patterns.append(name)
    except:
        pass
    
    is_scam = confidence >= 40
    
    scam_alert = None
    if is_scam:
        scam_alert = {
            "is_scam": True,
            "confidence": min(confidence, 100),
            "detected_patterns": detected_patterns,
            "senior_message": "STOP! This appears to be a SCAM.",
            "action_advice": "Close this window immediately."
        }
    
    return {
        "url": "screen://local",
        "domain": "local", 
        "media_score": min(confidence, 100),
        "media_color": "high" if is_scam else "low",
        "reasons": ["Scam detected"] if is_scam else [],
        "scam_alert": scam_alert
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="error")
