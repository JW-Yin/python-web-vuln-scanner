from urllib.parse import urlparse
from urllib.parse import quote


def normalize_url(url):
    """URL规范化"""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not url.endswith("/"):
        url += "/"
    return url

    
def get_domain(url):
    """提取域名"""
    parsed = urlparse(url)
    return parsed.netloc
    
def is_same_domain(url1, url2):
    """判断是否同域名"""
    return get_domain(url1) == get_domain(url2)
    

def is_valid_link(url, base_domain):
    """判断链接是否有效（同域名、非静态文件）"""
    if not is_same_domain(url, base_domain):
        return False
    if url.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif")):
        return False
    return True

def filter_urls(urls, base_domain, visited=None):
    """过滤URL：同域名、未访问、非静态文件"""
    if visited is None:
        visited = set()
    filtered = []
    for url in urls:
        if url not in visited and is_valid_link(url, base_domain):
            filtered.append(url)
    return filtered

def add_query_param(url, param, value):
    """向URL添加查询参数"""
    parsed = urlparse(url)
    query = parsed.query
    if query:
        query += f"&{param}={value}"
    else:
        query = f"{param}={value}"
    new_url = parsed._replace(query=query).geturl()
    return new_url
    
def encode_payload(payload):
    """对payload进行编码（URL编码、HTML实体等）"""
    return quote(payload)
