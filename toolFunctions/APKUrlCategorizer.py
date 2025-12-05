# Counts category matches across all URLs + lists raw uncategorized URLs

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
    
    # Count categories and collect uncategorized
    category_counts = {cat: 0 for cat in categories.keys()}
    uncategorized_urls = []
    
    for url in all_urls:
        cats = find_categories(url)
        if not cats:
            uncategorized_urls.append(url)
        else:
            for cat in cats:
                category_counts[cat] += 1
    
    # Write results
    with open(output_file, 'w', encoding='utf-8') as f:
        # Uncategorized URLs first
        for url in uncategorized_urls:
            f.write(url + "\n")
        f.write("\n")
        
        # Category counts (sorted by name)
        sorted_cats = sorted(category_counts.keys())
        for cat in sorted_cats:
            count = category_counts[cat]
            f.write(f"{cat}: {count}\n")
    
    print(f"Total URLs: {len(all_urls)}")
    print(f"Uncategorized: {len(uncategorized_urls)}")
    print(f"Saved to {output_file}")

if __name__ == "__main__":
    main()
