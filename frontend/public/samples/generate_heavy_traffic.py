#!/usr/bin/env python3
"""
Generate 100,000 realistic Nginx access log lines.
- 70% Human Traffic (70,000 requests)
- 30% SEO/AI Bot Traffic (30,000 requests)
- Global IP addresses across diverse ASNs
- Realistic timestamps, status codes, URLs, referrers, response sizes
"""

import os
import random
import ipaddress
from datetime import datetime, timedelta

TOTAL_REQUESTS = 100000
BOT_REQUESTS = 30000
HUMAN_REQUESTS = 70000

# Base time for logs (simulating a 24-hour period on 15/Aug/2026)
START_TIME = datetime(2026, 8, 15, 0, 0, 0)
DURATION_SECONDS = 86400

# Top SEO & AI Bots configuration
# Each bot: (group, name, share_weight, ip_subnets, user_agents, path_weights)
BOT_CONFIGS = [
    # Googlebot
    {
        "group": "Google",
        "name": "Googlebot",
        "weight": 25,
        "subnets": ["66.249.64.0/20", "66.249.70.0/20", "66.249.79.0/20"],
        "uas": [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Googlebot-Image/1.0",
        ],
        "paths": ["/robots.txt", "/sitemap.xml", "/", "/products", "/products/item-{id}", "/blog", "/blog/nginx-tuning-guide", "/docs/api", "/pricing", "/features"]
    },
    # Google Other / Ads
    {
        "group": "Google",
        "name": "GoogleOther",
        "weight": 5,
        "subnets": ["66.249.64.0/20", "66.249.76.0/20"],
        "uas": [
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36 (compatible; GoogleOther)",
            "AdsBot-Google (+http://www.google.com/adsbot.html)"
        ],
        "paths": ["/", "/pricing", "/products", "/landing/special-offer"]
    },
    # Bingbot
    {
        "group": "Microsoft",
        "name": "Bingbot",
        "weight": 14,
        "subnets": ["40.77.167.0/24", "157.55.39.0/24", "207.46.13.0/24", "13.66.139.0/24"],
        "uas": [
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        ],
        "paths": ["/robots.txt", "/sitemap.xml", "/", "/products", "/products/item-{id}", "/blog", "/about", "/pricing"]
    },
    # AhrefsBot
    {
        "group": "AhrefsBot",
        "name": "AhrefsBot",
        "weight": 10,
        "subnets": ["185.191.171.0/24", "51.222.253.0/24", "54.36.148.0/24"],
        "uas": [
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
        ],
        "paths": ["/robots.txt", "/sitemap.xml", "/", "/products", "/blog", "/blog/zero-downtime-deployments", "/docs/getting-started", "/pricing", "/features"]
    },
    # SemrushBot
    {
        "group": "SemrushBot",
        "name": "SemrushBot",
        "weight": 8,
        "subnets": ["185.191.171.0/24", "46.229.168.0/24", "185.220.101.0/24"],
        "uas": [
            "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"
        ],
        "paths": ["/robots.txt", "/", "/products", "/pricing", "/blog", "/faq", "/contact"]
    },
    # YandexBot
    {
        "group": "YandexBot",
        "name": "YandexBot",
        "weight": 7,
        "subnets": ["77.88.5.0/24", "87.250.224.0/24", "178.154.239.0/24", "95.108.213.0/24"],
        "uas": [
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
        ],
        "paths": ["/robots.txt", "/sitemap.xml", "/", "/products", "/about", "/blog", "/docs"]
    },
    # Baiduspider
    {
        "group": "Baidu Spider",
        "name": "Baidu Spider",
        "weight": 6,
        "subnets": ["180.76.15.0/24", "220.181.108.0/24", "123.125.71.0/24", "116.179.32.0/24"],
        "uas": [
            "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"
        ],
        "paths": ["/robots.txt", "/", "/products", "/docs", "/about", "/news"]
    },
    # ByteDance / Bytespider
    {
        "group": "ByteDance",
        "name": "Bytespider",
        "weight": 6,
        "subnets": ["110.249.201.0/24", "110.249.202.0/24", "111.225.148.0/24"],
        "uas": [
            "Mozilla/5.0 (compatible; Bytespider; https://zhanzhang.toutiao.com/)",
            "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)",
            "TikTokSpider (compatible; tiktok-spider/1.0; +https://www.tiktok.com)"
        ],
        "paths": ["/", "/products", "/products/item-{id}", "/blog", "/videos/intro"]
    },
    # GPTBot & OAI-SearchBot
    {
        "group": "OpenAI",
        "name": "GPTBot",
        "weight": 5,
        "subnets": ["20.171.206.0/24", "20.171.207.0/24", "52.230.152.0/24"],
        "uas": [
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)"
        ],
        "paths": ["/robots.txt", "/sitemap.xml", "/", "/docs/api-reference", "/docs/getting-started", "/blog", "/about"]
    },
    # ClaudeBot
    {
        "group": "Anthropic",
        "name": "ClaudeBot",
        "weight": 4,
        "subnets": ["54.208.100.0/24", "34.234.10.0/24", "52.90.12.0/24"],
        "uas": [
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
        ],
        "paths": ["/robots.txt", "/", "/docs/api", "/docs/architecture", "/blog/optimizing-nginx", "/pricing"]
    },
    # Applebot
    {
        "group": "Applebot",
        "name": "Applebot",
        "weight": 3,
        "subnets": ["17.58.96.0/24", "17.58.98.0/24", "17.121.112.0/24"],
        "uas": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) (Applebot/0.1; +http://www.apple.com/go/applebot)"
        ],
        "paths": ["/robots.txt", "/sitemap.xml", "/", "/products", "/apps/ios", "/support"]
    },
    # Facebook / Meta
    {
        "group": "Facebook/Meta",
        "name": "Facebook External Hit",
        "weight": 3,
        "subnets": ["157.240.22.0/24", "31.13.65.0/24", "69.171.224.0/24"],
        "uas": [
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "Mozilla/5.0 (compatible; Facebot; +http://facebook.com/externalhit_uatext.php)",
            "Mozilla/5.0 (compatible; meta-externalagent/1.1; +https://developers.facebook.com/docs/sharing/webmasters/crawler)"
        ],
        "paths": ["/", "/blog/nginx-tuning-guide", "/products/item-{id}", "/pricing", "/features"]
    },
    # Other SEO & Social Bots (PetalBot, DuckDuckBot, Sogou, Twitterbot, LinkedInBot)
    {
        "group": "Other Crawlers",
        "name": "Various Crawlers",
        "weight": 4,
        "subnets": ["114.119.130.0/24", "50.16.241.0/24", "106.120.173.0/24", "199.16.157.0/24", "108.174.10.0/24", "216.244.66.0/24", "144.76.108.0/24"],
        "uas": [
            "Mozilla/5.0 (compatible; PetalBot; +https://aspiegel.com/petalbot)",
            "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
            "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
            "Twitterbot/1.0",
            "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
            "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
            "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)"
        ],
        "paths": ["/robots.txt", "/", "/products", "/blog", "/feed.xml"]
    }
]

# Global Human IP Pools & ASNs
HUMAN_REGIONS = [
    # North America
    {
        "region": "North America",
        "weight": 35,
        "subnets": [
            "73.15.24.0/22", "67.180.12.0/22", "98.210.45.0/22",   # Comcast US
            "108.200.32.0/22", "12.180.90.0/22", "76.240.11.0/22", # AT&T US
            "100.1.48.0/22", "71.250.84.0/22",                    # Verizon US
            "142.147.10.0/22", "97.80.60.0/22",                   # Charter/Spectrum US
            "99.230.40.0/22", "142.162.20.0/22",                  # Bell / Rogers CA
            "189.130.50.0/22", "201.140.70.0/22"                  # Telmex MX
        ]
    },
    # Europe
    {
        "region": "Europe",
        "weight": 30,
        "subnets": [
            "80.130.12.0/22", "217.230.44.0/22",                  # Deutsche Telekom DE
            "90.60.25.0/22", "86.200.18.0/22",                    # Orange FR
            "86.130.80.0/22", "81.150.40.0/22",                   # British Telecom GB
            "82.10.100.0/22", "86.10.50.0/22",                    # Virgin Media GB
            "84.80.30.0/22", "213.84.15.0/22",                    # KPN NL
            "80.30.70.0/22", "213.96.110.0/22",                   # Telefonica ES
            "79.20.90.0/22", "82.50.140.0/22",                    # Telecom Italia IT
            "81.224.60.0/22", "83.250.10.0/22",                   # Telia SE
            "178.192.40.0/22",                                     # Swisscom CH
            "83.20.110.0/22"                                       # Orange PL
        ]
    },
    # Asia-Pacific
    {
        "region": "Asia-Pacific",
        "weight": 25,
        "subnets": [
            "49.32.10.0/22", "49.34.80.0/22", "157.34.120.0/22",  # Reliance Jio IN
            "122.160.40.0/22", "182.72.10.0/22",                  # Bharti Airtel IN
            "60.32.90.0/22", "133.242.50.0/22",                   # NTT JP
            "126.150.30.0/22", "126.200.70.0/22",                 # SoftBank JP
            "121.130.20.0/22", "211.200.80.0/22",                 # Korea Telecom KR
            "144.130.15.0/22", "139.130.45.0/22",                 # Telstra AU
            "116.86.50.0/22", "165.21.90.0/22",                   # Singtel SG
            "114.32.110.0/22", "220.130.40.0/22",                 # Chunghwa TW
            "180.240.60.0/22", "125.160.30.0/22",                 # PT Telkom ID
            "113.160.70.0/22"                                      # VNPT VN
        ]
    },
    # South America, Middle East & Africa
    {
        "region": "Rest of World",
        "weight": 10,
        "subnets": [
            "179.180.20.0/22", "201.20.50.0/22",                  # Claro BR
            "177.100.40.0/22",                                     # Vivo BR
            "190.190.10.0/22",                                     # Telecom Argentina AR
            "84.235.60.0/22",                                      # STC SA
            "94.200.30.0/22",                                      # Etisalat AE
            "105.208.40.0/22",                                     # Vodacom ZA
            "105.112.20.0/22",                                     # MTN NG
            "156.192.50.0/22"                                      # Telecom Egypt EG
        ]
    }
]

# Human User Agents
HUMAN_UAS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    # Chrome Android / Mobile
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.103 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36",
    # Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Firefox Windows & Linux
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
    # Edge Windows & Mac
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.2651.105",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.2651.98",
]

# Realistic Human URL endpoints & page paths
PAGE_PATHS = [
    ("/", 15),
    ("/products", 12),
    ("/products/item-{id}", 18),
    ("/pricing", 8),
    ("/features", 6),
    ("/blog", 7),
    ("/blog/nginx-tuning-guide", 5),
    ("/blog/zero-downtime-deployments", 4),
    ("/blog/web-security-best-practices", 3),
    ("/docs/getting-started", 4),
    ("/docs/api-reference", 3),
    ("/about", 3),
    ("/contact", 2),
    ("/login", 3),
    ("/dashboard", 4),
    ("/cart", 3),
    ("/checkout", 2),
]

STATIC_ASSETS = [
    ("/css/app.min.css", 200, 14850),
    ("/css/theme.css", 200, 4200),
    ("/js/bundle.min.js", 200, 68420),
    ("/js/vendor.js", 200, 112400),
    ("/images/hero.webp", 200, 84200),
    ("/images/logo.svg", 200, 3200),
    ("/images/product-{id}.webp", 200, 45100),
    ("/favicon.ico", 200, 1150),
]

API_ENDPOINTS = [
    ("GET", "/api/v1/user/me", 200, 420),
    ("POST", "/api/v1/auth/login", 200, 280),
    ("GET", "/api/v1/cart", 200, 1150),
    ("POST", "/api/v1/cart/items", 200, 340),
    ("GET", "/api/v1/search?q={query}", 200, 4820),
    ("GET", "/api/v1/notifications", 200, 520),
    ("GET", "/api/v1/analytics/realtime", 200, 890),
]

SEARCH_QUERIES = ["nginx", "docker", "sysadmin", "ssl", "kubernetes", "performance", "monitoring", "caching", "firewall", "security"]

EXTERNAL_REFERRERS = [
    "https://www.google.com/",
    "https://www.google.com/search?q=sysadmin+toolkit",
    "https://www.bing.com/search?q=nginx+log+analyzer",
    "https://t.co/xyz8912",
    "https://news.ycombinator.com/",
    "https://www.reddit.com/r/sysadmin/",
    "https://www.linkedin.com/feed/",
    "https://github.com/trending",
]

def generate_random_ip(subnet_str):
    """Generate a random host IP within a CIDR subnet."""
    net = ipaddress.ip_network(subnet_str, strict=False)
    # Pick a random host offset (avoid network and broadcast)
    num_hosts = net.num_addresses
    if num_hosts <= 2:
        return str(net.network_address)
    offset = random.randint(1, num_hosts - 2)
    return str(net.network_address + offset)

def format_log_time(dt):
    # Nginx format: 15/Aug/2026:14:22:31 +0000
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def main():
    print("Generating 100,000 realistic Nginx access log records...")
    random.seed(42)  # Deterministic seed for reproducible quality

    # Pre-generate IP pools for human users to simulate multiple sessions per IP
    human_ip_pool = []
    for region in HUMAN_REGIONS:
        subnets = region["subnets"]
        weight = region["weight"]
        # Generate ~100-150 distinct IPs per region
        for _ in range(weight * 50):
            sub = random.choice(subnets)
            human_ip_pool.append({
                "ip": generate_random_ip(sub),
                "ua": random.choice(HUMAN_UAS)
            })

    # Pre-generate IP pools for bots
    bot_ip_pools = {}
    for bot in BOT_CONFIGS:
        bname = bot["name"]
        bot_ip_pools[bname] = []
        for _ in range(60):
            sub = random.choice(bot["subnets"])
            bot_ip_pools[bname].append(generate_random_ip(sub))

    log_entries = []

    # -------------------------------------------------------------
    # 1. Generate 30,000 Bot Requests (30%)
    # -------------------------------------------------------------
    bot_weights = [b["weight"] for b in BOT_CONFIGS]
    total_bot_weight = sum(bot_weights)
    bot_cum_weights = []
    running = 0
    for w in bot_weights:
        running += w
        bot_cum_weights.append(running)

    for i in range(BOT_REQUESTS):
        # Pick bot by weight
        r = random.uniform(0, total_bot_weight)
        idx = 0
        for b_idx, cum in enumerate(bot_cum_weights):
            if r <= cum:
                idx = b_idx
                break
        bot = BOT_CONFIGS[idx]
        bname = bot["name"]

        ip = random.choice(bot_ip_pools[bname])
        ua = random.choice(bot["uas"])
        path_template = random.choice(bot["paths"])
        path = path_template.replace("{id}", str(random.randint(100, 999)))

        # Method
        method = "GET"
        if "robots.txt" in path or "sitemap.xml" in path:
            method = "GET" if random.random() < 0.9 else "HEAD"

        # Timestamp distributed across 24 hours with small cluster bursts
        sec_offset = random.randint(0, DURATION_SECONDS - 1)
        req_time = START_TIME + timedelta(seconds=sec_offset)

        # Status Code & Body Size
        status_roll = random.random()
        if path == "/robots.txt":
            status = 200
            size = random.randint(140, 280)
        elif path == "/sitemap.xml":
            status = 200
            size = random.randint(4800, 18500)
        elif status_roll < 0.88:
            status = 200
            size = random.randint(2400, 38500)
        elif status_roll < 0.94:
            status = 304  # Not Modified (conditional request)
            size = 0
        elif status_roll < 0.97:
            status = 301  # Redirect
            size = random.randint(160, 320)
        else:
            status = 404  # Not Found
            size = random.randint(150, 450)

        referrer = "-"
        if random.random() < 0.15 and path not in ["/robots.txt", "/sitemap.xml"]:
            referrer = "https://example.com/"

        http_ver = "HTTP/1.1" if random.random() < 0.75 else "HTTP/2.0"
        time_str = format_log_time(req_time)

        # Combined format: IP - - [time] "METHOD /path HTTP/x.x" status size "referer" "user_agent"
        line = f'{ip} - - [{time_str}] "{method} {path} {http_ver}" {status} {size} "{referrer}" "{ua}"'
        log_entries.append((req_time, line))

    # -------------------------------------------------------------
    # 2. Generate 70,000 Human Requests (70%)
    # -------------------------------------------------------------
    # We will simulate browsing sessions (page hit followed by static assets & API calls)
    while len(log_entries) < TOTAL_REQUESTS:
        user = random.choice(human_ip_pool)
        ip = user["ip"]
        ua = user["ua"]

        # Session start time
        session_sec = random.randint(0, DURATION_SECONDS - 600)
        session_time = START_TIME + timedelta(seconds=session_sec)

        # Number of page views in this session (1 to 5)
        num_pages = random.randint(1, 4)
        prev_page = None

        for p in range(num_pages):
            if len(log_entries) >= TOTAL_REQUESTS:
                break

            # Pick page
            path_tuple = random.choices([p[0] for p in PAGE_PATHS], weights=[p[1] for p in PAGE_PATHS])[0]
            page_path = path_tuple.replace("{id}", str(random.randint(100, 999)))

            # Timestamp: stepped forward by a few seconds
            page_time = session_time + timedelta(seconds=random.randint(2, 45))
            session_time = page_time

            # Referrer
            if prev_page is None:
                if random.random() < 0.65:
                    ref = random.choice(EXTERNAL_REFERRERS)
                else:
                    ref = "-"
            else:
                ref = f"https://example.com{prev_page}"
            prev_page = page_path

            # Status code
            roll = random.random()
            if roll < 0.90:
                status = 200
                size = random.randint(3500, 48000)
            elif roll < 0.95:
                status = 304
                size = 0
            elif roll < 0.98:
                status = 302
                size = random.randint(180, 400)
            elif roll < 0.995:
                status = 404
                size = random.randint(180, 520)
            else:
                status = 500
                size = random.randint(190, 600)

            http_ver = "HTTP/2.0" if random.random() < 0.65 else "HTTP/1.1"
            time_str = format_log_time(page_time)
            line = f'{ip} - - [{time_str}] "GET {page_path} {http_ver}" {status} {size} "{ref}" "{ua}"'
            log_entries.append((page_time, line))

            # Trigger asset downloads (CSS, JS, images)
            if status == 200 and random.random() < 0.85:
                num_assets = random.randint(2, 5)
                selected_assets = random.sample(STATIC_ASSETS, min(num_assets, len(STATIC_ASSETS)))
                for a_path, a_stat, a_size in selected_assets:
                    if len(log_entries) >= TOTAL_REQUESTS:
                        break
                    asset_path = a_path.replace("{id}", str(random.randint(1, 20)))
                    asset_time = page_time + timedelta(milliseconds=random.randint(50, 800))
                    a_ref = f"https://example.com{page_path}"
                    actual_stat = 304 if random.random() < 0.35 else 200
                    actual_size = 0 if actual_stat == 304 else int(a_size * random.uniform(0.9, 1.1))
                    a_time_str = format_log_time(asset_time)
                    a_line = f'{ip} - - [{a_time_str}] "GET {asset_path} {http_ver}" {actual_stat} {actual_size} "{a_ref}" "{ua}"'
                    log_entries.append((asset_time, a_line))

            # Trigger API calls
            if status == 200 and random.random() < 0.50:
                if len(log_entries) >= TOTAL_REQUESTS:
                    break
                api = random.choice(API_ENDPOINTS)
                api_method, api_path_tpl, api_stat, api_size = api
                api_path = api_path_tpl.replace("{query}", random.choice(SEARCH_QUERIES))
                api_time = page_time + timedelta(seconds=random.randint(1, 10))
                api_ref = f"https://example.com{page_path}"
                api_time_str = format_log_time(api_time)
                api_line = f'{ip} - - [{api_time_str}] "{api_method} {api_path} {http_ver}" {api_stat} {api_size} "{api_ref}" "{ua}"'
                log_entries.append((api_time, api_line))

    # Ensure exact length of 100,000
    log_entries = log_entries[:TOTAL_REQUESTS]

    # Sort all entries by timestamp for realistic chronological order
    print("Sorting log entries chronologically...")
    log_entries.sort(key=lambda x: x[0])

    output_path = os.path.join(os.path.dirname(__file__), "heavy-traffic.log")
    print(f"Writing {len(log_entries)} log lines to {output_path}...")
    with open(output_path, "w", encoding="utf-8") as f:
        for _, line in log_entries:
            f.write(line + "\n")

    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"✅ Generated {len(log_entries)} logs successfully! File size: {file_size_mb:.2f} MB")

if __name__ == "__main__":
    main()
