# Simple URL category finder
# Reads URLs from file, finds matching categories, outputs unique categories to unique_categories.txt

import re

# Categories and their keywords
categories = {
    'api_calls': ['api', 'restserver', 'oauth', 'sdk', 'svc', 'service'],
    'ad_requests': ['ad', 'ads', 'getad', 'showad', 'click', 'impression', 'banner', 'interstitial'],
    'google_services': ['google', 'gstatic', 'googleapis', 'doubleclick', 'googlesyndication'],
    'facebook': ['facebook', 'fbcdn', 'graph.facebook'],
    'twitter': ['twitter', 'twimg', 't.twitter'],
    'game_networks': ['gameloft', 'scoreloop', 'herocraft', 'glu', 'outfit7'],
    'app_markets': ['play.google.com', 'market.android.com', 'amazon.comgpmas', '91.com'],
    'c2_servers': ['lebar.gicp.net', 'master-code.ru', 'go108', 'anzhuo7', '5k3g', 'msreplier', 'hidroid'],
    'sms_fraud': ['nnetonline', 'sms', 'mms', 'monternet', 'zong'],
    'adult': ['porn', 'youporn', 'xxx', 'adult', 'xvideo'],
    'file_transfer': ['download', 'upload', 'file', 'apk', 'zip'],
    'tracking': ['log', 'track', 'event', 'metric'],
    'config_endpoints': ['config', 'init', 'check', 'report', 'getinfo'],
    'static_content': ['static', 'image', 'images', 'img', 'css', 'js', 'resource', 'resources', 'asset', 'assets', 'content', 'lib', 'media', 'schema', 'schemas'],
    'malware_paths': ['update', 'install', 'flash', 'droidapp', 'latest.php', 'order.php'],
    'dynamic_dns': ['gicp.net', 'no-ip', 'dyndns', 'duckdns'],
    'chinese_domains_expanded': ['baidu', 'qq', 'sina', 'taobao', 'aliexpress', 'tmall', 'jd.com'],
    'app_dev': ['appspot', 'herokuapp', 'firebaseio', 'parseapp'],
    'webview_endpoints': ['webview', 'bridge', 'mraid', 'raid'],
    'score_endpoints': ['score', 'leaderboard', 'rank', 'highscore', 'achievement'],
    'media_files': ['.mp4', '.mp3', '.jpg', '.png', '.gif', '.xml', '.json', '.js', '.css'],
    'vpon_specific': ['vpon.com'],
    'mydas_specific': ['mydas.mobi'],
    'wooboo_specific': ['wooboo'],
    'casee_specific': ['casee'],
    'microsoft': ['microsoft', 'azure', 'live', 'outlook', 'skype'],
    'amazon': ['amazonaws', 'amazon']
}

def find_categories(url):
    # Lowercase URL
    url_lower = url.lower()
    
    # Split URL into parts (domain, path, query)
    main = url_lower.split('://', 1)[-1] if '://' in url_lower else url_lower
    parts = main.replace('?', '/').replace('&', '/').replace('=', '/').split('/')
    parts = [p for p in parts if p and len(p) > 1]
    
    matches = []
    
    # Check each category
    for cat_name, keywords in categories.items():
        for keyword in keywords:
            # Check if keyword appears in any part
            for part in parts:
                if keyword in part:
                    matches.append(cat_name)
                    break
            if cat_name in matches:
                break
    
    return list(set(matches)) or ['uncategorized']

def main():
    input_file = "unique_urls.txt"
    output_file = "unique_categories.txt"
    
    # Read input file
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]
    
    # Find all categories
    all_cats = set()
    for line in lines:
        cats = find_categories(line)
        all_cats.update(cats)
    
    # Sort and save unique categories
    unique_cats = sorted(list(all_cats))
    with open(output_file, 'w') as f:
        f.write('\n'.join(unique_cats))
    
    print(f"Found {len(unique_cats)} unique categories")
    print("Wrote to", output_file)

if __name__ == "__main__":
    main()
