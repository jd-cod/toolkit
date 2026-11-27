import random
import os
from datetime import datetime, timedelta

def generate_multi_vector_logs():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "multi-vector-attack.log")
    random.seed(7)  # the same file on every run
    total_lines = 50000
    
    # Base start time: 14 hours span
    start_time = datetime(2026, 8, 15, 0, 0, 0)
    
    # Profiles
    legit_ips = [
        ("66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot"),
        ("66.249.66.2", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot"),
        ("40.77.167.1", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "Bingbot"),
        ("54.36.148.1", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "AhrefsBot"),
        ("142.250.180.14", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0", "Human"),
        ("172.56.21.89", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15", "Human"),
        ("84.17.45.12", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15", "Human"),
        ("103.21.244.5", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0", "Human")
    ]
    
    attacker_ips = [
        ("185.220.101.5", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Spoofed Googlebot (Tor)"),
        ("185.220.101.7", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Spoofed Googlebot (Tor)"),
        ("194.26.29.112", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "Spoofed Bingbot (RU VPS)"),
        ("45.154.255.8", "python-requests/2.31.0", "Scanner (NL)"),
        ("91.240.118.172", "Go-http-client/1.1", "Exploit Prober"),
        ("193.142.146.33", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) zgrab/0.x", "ZGrab Scanner")
    ]
    
    legit_paths = [
        ("GET", "/", 200, 14200),
        ("GET", "/products", 200, 28400),
        ("GET", "/products/item-492", 200, 18500),
        ("GET", "/pricing", 200, 9200),
        ("GET", "/about", 200, 6100),
        ("GET", "/blog/nginx-tuning-guide", 200, 32100),
        ("GET", "/css/theme.css", 200, 4030),
        ("GET", "/js/bundle.min.js", 200, 64200),
        ("GET", "/images/hero.webp", 200, 92400)
    ]
    
    attack_paths = [
        ("POST", "/xmlrpc.php", 403, 204),
        ("GET", "/wp-login.php", 403, 204),
        ("GET", "/.env", 404, 162),
        ("GET", "/.git/config", 404, 162),
        ("POST", "/api/v1/auth/login", 401, 320),
        ("GET", "/administrator/index.php", 404, 162),
        ("GET", "/autodiscover/autodiscover.json", 404, 162)
    ]
    
    lines = []
    
    for i in range(total_lines):
        # Progress across 14 hours (00:00 to 14:00)
        progress = i / float(total_lines)
        curr_time = start_time + timedelta(seconds=progress * 14 * 3600 + random.randint(0, 3))
        ts_str = curr_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        
        # Attack spike occurs between 09:30 and 11:30 (hours 9.5 to 11.5)
        hour_frac = (curr_time - start_time).total_seconds() / 3600.0
        is_attack_window = 9.5 <= hour_frac <= 11.5
        
        if is_attack_window and random.random() < 0.75:
            # Generate Attack Line
            ip_info = random.choice(attacker_ips)
            path_info = random.choice(attack_paths)
            ip, ua, _ = ip_info
            method, path, status, size = path_info
            ref = "-" if random.random() < 0.8 else "https://google.com/"
        else:
            # Generate Legitimate Line
            ip_info = random.choice(legit_ips)
            path_info = random.choice(legit_paths)
            ip, ua, _ = ip_info
            method, path, status, size = path_info
            ref = "-" if random.random() < 0.5 else "https://www.google.com/search?q=nginx"
            
        line = f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'
        lines.append(line)
        
    with open(output_path, "w") as f:
        f.write("\n".join(lines) + "\n")
        
    print(f"Generated {len(lines)} lines at {output_path}")

generate_multi_vector_logs()
