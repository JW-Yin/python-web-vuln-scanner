from utils.http_client import HttpClient
from bs4 import BeautifulSoup
from urllib.parse import urljoin,urlparse

from utils.logger import ScannerLogger
from config.settings import Config


class Crawler:
    def __init__(self, http_client: HttpClient, logger: ScannerLogger, config: Config):
        self.client = http_client
        self.logger = logger
        self.config = config

        self.visited = set()
        self.to_visit = []
        self.discovered_forms = []
        # determine base host to avoid crawling external domains
        from urllib.parse import urlparse
        start = self.config.get('scanner', 'url')
        try:
            self.base_netloc = urlparse(start).netloc
        except Exception:
            self.base_netloc = None

    def crawl(self, start_url):
        """
        爬取网站
        返回: (链接列表, 表单列表)
        """
        self.to_visit.append((start_url, 0))
        max_depth = self.config.get("scanner", "max_depth")

        while self.to_visit:
            current_url, depth = self.to_visit.pop(0)
            if depth > max_depth:
                continue

            if not self.should_crawl(current_url):
                continue

            self.logger.info(f"爬取: {current_url} (深度: {depth})")
            try:
                links, forms = self.crawl_page(current_url)
                self.visited.add(current_url)
                self.discovered_forms.extend(forms)

                for link in links:
                    if link not in self.visited:
                        self.to_visit.append((link, depth + 1))
            except Exception as e:
                self.logger.error(f"爬取失败: {current_url} 错误: {e}")

        return list(self.visited), self.discovered_forms

    def crawl_page(self, url):
        """爬取单个页面"""
        response = self.client.get(url)
        html = response.text
        links = self.discover_links(html, url)
        forms = self.discover_forms(html, url)
        return links, forms

    def discover_links(self, html, base_url):
        """发现新链接"""
        links = []
        soup = BeautifulSoup(html, "lxml")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(base_url, href)
            links.append(full_url)
        return links

    def discover_forms(self, html, url):
        """发现表单"""
        forms = []
        soup = BeautifulSoup(html, "lxml")
        for form in soup.find_all("form"):
            form_details = {
                "url": url,
                "action": form.get("action"),
                "method": form.get("method", "get").lower(),
                "inputs": [],
            }
            for input_tag in form.find_all("input"):
                input_type = input_tag.get("type", "text")
                input_name = input_tag.get("name")
                input_value = input_tag.get("value", "")
                form_details["inputs"].append({"type": input_type, "name": input_name, "value": input_value})
            forms.append(form_details)
        return forms

    def should_crawl(self, url):
        """判断是否应该爬取该URL"""
        if url in self.visited:
            return False
        if self.base_netloc:
            if urlparse(url).netloc and urlparse(url).netloc != self.base_netloc:
                return False
        return True

    def get_targets(self):
        """获取所有目标（URL和表单）"""
        return list(self.visited), self.discovered_forms
