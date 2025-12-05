# Reads unique_urls.txt, outputs ALL categories found + raw uncategorized URLs

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
    url_lower = url.lower()
    main = url_lower.split('://', 1)[-1] if '://' in url_lower else url_lower
    parts = main.replace('?', '/').replace('&', '/').replace('=', '/').split('/')
    parts = [p for p in parts if p and len(p) > 1]
    
    matches = []
    for cat_name, keywords in categories.items():
        for keyword in keywords:
            for part in parts:
                if keyword in part:
                    matches.append(cat_name)
                    break
            if cat_name in matches:
                break
    return matches

def main():
    input_file = "unique_urls.txt"
    output_file = "results.txt"
    
    # Read all URLs
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        all_urls = [line.strip() for line in f if line.strip()]
    
    # Find all categories that appear
    found_categories = set()
    uncategorized_urls = []
    
    for url in all_urls:
        cats = find_categories(url)
        if cats:
            found_categories.update(cats)
        else:
            uncategorized_urls.append(url)
    
    # Write results: categories first, then uncategorized URLs
    with open(output_file, 'w', encoding='utf-8') as f:
        # Write found categories
        sorted_cats = sorted(list(found_categories))
        f.write("# FOUND CATEGORIES\n")
        for cat in sorted_cats:
            f.write(cat + "\n")
        f.write("\n# UNCATEGORIZED RAW URLs\n")
        for url in uncategorized_urls:
            f.write(url + "\n")
    
    print(f"Found {len(sorted_cats)} categories")
    print(f"Uncategorized URLs: {len(uncategorized_urls)}")
    print(f"Saved to {output_file}")

if __name__ == "__main__":
    main()
