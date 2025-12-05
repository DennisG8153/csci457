class APKUrlCategorizer:
    def __init__(self): # Initialize token groups for URL categorization
        self.token_groups = {
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
            'static_content': ['static', 'image', 'images', 'img', 'css', 'js', 'resource',
                               'resources', 'asset', 'assets', 'content', 'lib', 'media',
                               'schema', 'schemas'],
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
            'amazon': ['amazonaws', 'amazon'],
        }
        # Define the order of categories for consistent output
        self.category_order = list(self.token_groups.keys())
        self.boundary_limited = {
            'ad', 'ads', 'log', 'file'
        }
    # Check if a segment contains a token with boundary conditions
    def _segment_contains(self, segment: str, token: str) -> bool:
        """Stricter match only for tokens in boundary_limited."""
        if token not in self.boundary_limited:
            return token in segment
        import re
        parts = re.split(r'[^a-z0-9-]', segment.lower())
        return token in parts
    # Check if the URL matches a given token
    def _url_matches_token(self, url_lower: str, token: str) -> bool:
        main = url_lower.split('://', 1)[-1]
        segments = []
        
        for part in main.replace('?', '/').replace('&', '/').replace('=', '/').split('/'):
            if part and len(part) > 1:
                segments.append(part)

        for seg in segments:
            if self._segment_contains(seg, token):
                return True
        return False
    # Categorize a URL into multiple categories based on token matches
    def categorize_url_multi(self, url: str):
        if not url or not url.strip():
            return ['empty']
        u = url.lower()

        matches = []
        for g in self.category_order:
            for tok in self.token_groups[g]:
                if self._url_matches_token(u, tok):
                    matches.append(g)
                    break
        return ['uncategorized'] if not matches else matches
    # Analyze a file of URLs and write multi-category mappings to an output file
    def analyze_file_multi(self, path: str, out_path: str = "url_multi_categories.txt"):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]

        lines = []
        for url in urls:
            cats = self.categorize_url_multi(url)
            cat_str = ",".join(cats)
            lines.append(f"{cat_str}\t{url}")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Wrote multi-category mapping to {out_path}")

# Main function to run the APKUrlCategorizer on a sample file
def main():
    analyzer = APKUrlCategorizer()
    analyzer.analyze_file_multi("unique_urls.txt")

# Run the main function if this script is executed
if __name__ == "__main__":
    main()
