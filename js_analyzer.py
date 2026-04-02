#!/usr/bin/env python3
"""JavaScript analysis for phishing detection.

Extracts behavioral features from JavaScript code to detect phishing.
No regex phrases — analyzes code structure, API usage, obfuscation patterns.
"""

import re
import math
import json
import random
from collections import Counter
from pathlib import Path

import numpy as np


def extract_js_features(js_code: str) -> np.ndarray:
    """Extract 30 features from JavaScript code.

    These capture HOW the code behaves, not what words it contains.
    Phishing JS has distinct structural patterns from legitimate JS.
    """
    if not js_code:
        return np.zeros(30, dtype=np.float32)

    code = js_code
    cl = code.lower()
    code_len = len(code)

    # === OBFUSCATION STRUCTURAL DETECTION ===
    # Detect the STRUCTURE of obfuscation, not specific function names.
    # Obfuscated code has: hex variable names, string arrays, array shuffling,
    # self-executing functions, high variable count with low reuse.

    # 7. Hex-encoded variable names (_0x45a3, _0x5ce7, etc.)
    hex_vars = re.findall(r'\b_0x[0-9a-f]{3,}\b', cl)
    hex_var_ratio = len(hex_vars) / max(len(re.findall(r'\b[a-z_]\w*\b', cl)), 1)

    # 8. String arrays (common obfuscation pattern: var _0x45a3=[...])
    string_arrays = len(re.findall(r'var\s+_0x[0-9a-f]+\s*=\s*\[', cl))

    # 9. Array shuffling (self-executing loop that shifts array elements)
    array_shuffle = len(re.findall(r"\[.*?push.*?shift.*?\]", cl))

    # 10. Self-executing functions (IIFE)
    iife_count = len(re.findall(r'\(\s*function\s*\(', cl)) + len(re.findall(r'\(function\s*\(', cl))

    # 11. Location-based redirects hidden in array indexing
    has_location = bool(re.search(r'location|href', cl))
    has_window = cl.count('window')
    hidden_redirect = has_location and has_window and hex_var_ratio > 0.1

    # === CREDENTIAL HARVESTING ===

    # 7. Form input reading
    form_read_count = (
        len(re.findall(r'\.value\b', cl)) +
        len(re.findall(r'getelementbyid', cl)) +
        len(re.findall(r'queryselector', cl))
    )

    # 8. Password field access
    password_access = len(re.findall(r'type\s*=\s*["\']password', cl))

    # 9. Form submission hijacking
    form_submit = len(re.findall(r'\.submit\s*\(', cl))

    # 10. XMLHttpRequest/fetch (data exfiltration)
    xhr_count = cl.count('xmlhttprequest') + cl.count('new xmlhttp') + len(re.findall(r'\bfetch\s*\(', cl))

    # === DOM MANIPULATION ===

    # 11. document.write
    doc_write_count = cl.count('document.write(')

    # 12. innerHTML/outerHTML injection
    innerhtml_count = cl.count('.innerhtml') + cl.count('.outerhtml')

    # 13. createElement (injecting new elements)
    create_element = cl.count('createelement(')

    # 14. appendChild (adding elements to DOM)
    append_child = cl.count('appendchild(')

    # === NETWORK BEHAVIOR ===

    # 15. External domain references (URLs in the code)
    url_refs = len(re.findall(r'https?://[^\s"\'<>]+', code))

    # 16. WebSocket connections
    websocket_count = cl.count('new websocket(')

    # 17. POST requests (sending data out)
    post_count = len(re.findall(r'method\s*[:=]\s*["\']post', cl))

    # === REDIRECT BEHAVIOR ===

    # 18. Location changes
    location_count = (
        cl.count('location.href') + cl.count('location.replace') +
        cl.count('window.location') + len(re.findall(r'location\s*=', cl))
    )

    # 19. Meta refresh detection
    meta_refresh = len(re.findall(r'http-equiv.*refresh', cl))

    # 20. setTimeout/setInterval (delayed actions)
    timer_count = cl.count('settimeout(') + cl.count('setinterval(')

    # === COOKIE/STORAGE ACCESS ===

    # 21. Cookie access
    cookie_count = cl.count('document.cookie')

    # 22. localStorage/sessionStorage
    storage_count = cl.count('localstorage') + cl.count('sessionstorage')

    # === ANTI-ANALYSIS ===

    # 23. Developer tools detection
    devtools_detect = len(re.findall(r'devtools|debugger|console\.log.*check', cl))

    # 24. Anti-right-click
    rightclick_block = cl.count('contextmenu') + cl.count('oncontextmenu')

    # 25. Keyboard blocking (F12, Ctrl+U, etc)
    keyblock = len(re.findall(r'keydown|onkeydown', cl))

    # === STRUCTURAL FEATURES ===

    # 26. Code length
    length_score = min(1.0, code_len / 50000)

    # 27. Line count
    line_count = code.count('\n') + 1

    # 28. Comment ratio (phishing kits often have no comments)
    comment_lines = len(re.findall(r'//.*$', cl, re.M)) + len(re.findall(r'/\*.*?\*/', cl, re.S))
    comment_ratio = comment_lines / max(line_count, 1)

    # 29. Function count
    function_count = len(re.findall(r'\bfunction\b', cl)) + len(re.findall(r'=>', cl))

    # 30. String entropy (obfuscated code has high entropy)
    if code:
        freq = Counter(code)
        probs = [c / len(code) for c in freq.values()]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    else:
        entropy = 0

    return np.array([
        eval_count, atob_count, unescape_count, fromcharcode_count,
        escape_ratio, single_char_ratio, avg_var_len,
        form_read_count, password_access, form_submit, xhr_count,
        doc_write_count, innerhtml_count, create_element, append_child,
        url_refs, websocket_count, post_count,
        location_count, meta_refresh, timer_count,
        cookie_count, storage_count,
        devtools_detect, rightclick_block, keyblock,
        length_score, line_count, comment_ratio, entropy,
    ], dtype=np.float32)


JS_FEATURE_NAMES = [
    'eval_count', 'atob_count', 'unescape_count', 'fromcharcode_count',
    'escape_ratio', 'single_char_ratio', 'avg_var_len',
    'form_read_count', 'password_access', 'form_submit', 'xhr_count',
    'doc_write_count', 'innerhtml_count', 'create_element', 'append_child',
    'url_refs', 'websocket_count', 'post_count',
    'location_count', 'meta_refresh', 'timer_count',
    'cookie_count', 'storage_count',
    'devtools_detect', 'rightclick_block', 'keyblock',
    'length_score', 'line_count', 'comment_ratio', 'entropy',
]


def classify_js(js_code: str) -> tuple:
    """Classify JavaScript code as malicious or benign.

    Returns (risk_score, signals) where risk_score is 0.0-1.0.
    Detects obfuscation STRUCTURE, not specific function names.
    """
    if not js_code or len(js_code.strip()) < 20:
        return 0.0, []

    cl = js_code.lower()
    signals = []

    # === STRUCTURAL OBFUSCATION (catches hex-encoded phishing kit scripts) ===

    # Hex-encoded variable names (_0x45a3, _0x5ce7)
    hex_vars = re.findall(r'\b_0x[0-9a-f]{3,}\b', cl)
    all_vars = re.findall(r'\b[a-z_]\w*\b', cl)
    hex_var_ratio = len(hex_vars) / max(len(all_vars), 1)

    # String arrays (var _0x45a3=[...])
    string_arrays = len(re.findall(r'var\s+_0x[0-9a-f]+\s*=\s*\[', cl))

    # Array shuffling (push/shift patterns)
    array_shuffle = len(re.findall(r'push.*?shift|shift.*?push', cl))

    # IIFE (self-executing functions)
    iife_count = len(re.findall(r'\(\s*function\s*\(', cl))

    # Hidden redirect (location/href accessed through hex variables)
    has_location = bool(re.search(r'location|href', cl))
    has_window = cl.count('window')
    hidden_redirect = has_location and has_window and hex_var_ratio > 0.1

    # Score structural obfuscation
    obfuscation_score = 0.0
    if hex_var_ratio > 0.15:
        obfuscation_score += 0.3
        signals.append(f'hex-obfuscation ({len(hex_vars)} vars, {hex_var_ratio:.0%})')
    if string_arrays >= 1:
        obfuscation_score += 0.2
        signals.append(f'string-array-obfuscation ({string_arrays})')
    if array_shuffle >= 1:
        obfuscation_score += 0.25
        signals.append('array-shuffle')
    if iife_count >= 1 and hex_var_ratio > 0.1:
        obfuscation_score += 0.15
        signals.append('obfuscated-iife')
    if hidden_redirect:
        obfuscation_score += 0.35
        signals.append('hidden-redirect')

    # === CLASSIC OBFUSCATION (eval, atob, etc.) ===
    if cl.count('eval(') >= 3:
        signals.append(f'heavy-eval ({cl.count("eval(")})')
        obfuscation_score += 0.25
    if cl.count('atob(') + cl.count('btoa(') >= 2:
        signals.append('base64-decode')
        obfuscation_score += 0.15
    if cl.count('string.fromcharcode(') >= 2:
        signals.append('char-assembly')
        obfuscation_score += 0.20

    # === CREDENTIAL HARVESTING ===
    form_reads = cl.count('.value') + cl.count('getelementbyid') + cl.count('queryselector')
    password_access = len(re.findall(r'type\s*=\s*["\']password', cl))
    form_submit = cl.count('.submit(')
    xhr_count = cl.count('xmlhttprequest') + len(re.findall(r'\bfetch\s*\(', cl))

    if form_reads >= 5 and password_access >= 1:
        signals.append('credential-reading')
    if form_submit >= 1 and xhr_count >= 1:
        signals.append('form-hijack+exfil')

    # === DATA EXFILTRATION ===
    cookie_count = cl.count('document.cookie')
    if xhr_count >= 2 and (form_reads >= 3 or cookie_count >= 1):
        signals.append('data-exfiltration')

    # === SCORING ===
    score = min(1.0, obfuscation_score)

    # Combos
    if hidden_redirect and hex_var_ratio > 0.2:
        score = max(score, 0.8)  # Heavily obfuscated redirect = almost certainly malicious
    if string_arrays >= 1 and array_shuffle >= 1:
        score = max(score, 0.7)  # String array + shuffle = phishing kit pattern

    return score, signals
