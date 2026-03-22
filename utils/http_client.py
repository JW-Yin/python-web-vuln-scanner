import requests
from requests.exceptions import RequestException, Timeout, ConnectionError
from config.settings import Config
from utils.logger import ScannerLogger

class HttpClient:
    def __init__(self, config: Config, logger: ScannerLogger):
        """
        初始化HTTP客户端
        配置session、代理、超时、认证等
        :param config: 配置字典（从Config类加载的嵌套字典）
        """
        self.logger = logger
        self.config = config
        self.session = None; self.setup_session()
        
        self.logger.info("HTTP客户端初始化完成")

    def setup_session(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config.get("http", "user_agent")})
        self.session.verify = self.config.get("http", "verify_ssl")

    def get(self, url, **kwargs):
        """
        发送GET请求
        :param url: 请求URL
        :param kwargs: 额外参数（如params/headers等，会覆盖默认配置）
        :return: 响应对象/None（异常时返回None）
        """
        try:
            return self.session.get(url, timeout=self.config.get("http", "timeout"), **kwargs)
        except (Timeout, ConnectionError) as e:
            print(f"GET请求超时/连接失败 {url}：{str(e)}")
            return None
        except RequestException as e:
            print(f"GET请求异常 {url}：{str(e)}")
            return None

    def post(self, url, data=None, files=None, **kwargs):
        """
        发送POST请求，支持文件上传
        :param url: 请求URL
        :param data: POST数据（字典/字符串）
        :param files: 文件上传字典（{"file": open("test.txt", "rb")}）
        :param kwargs: 额外参数
        :return: 响应对象/None
        """
        try:
            return self.session.post(url, data=data, files=files, timeout=self.config.get("http", "timeout"), **kwargs)
        except (Timeout, ConnectionError) as e:
            print(f"POST请求超时/连接失败 {url}：{str(e)}")
            return None
        except RequestException as e:
            print(f"POST请求异常 {url}：{str(e)}")
            return None

    def request(self, method, url, **kwargs):
        """
        通用请求方法（支持GET/POST/PUT/DELETE等）
        :param method: 请求方法（大写：GET/POST/PUT/DELETE）
        :param url: 请求URL
        :param kwargs: 额外参数
        :return: 响应对象/None
        """
        try:
            return self.session.request(method.upper(), url, **kwargs)
        except (Timeout, ConnectionError) as e:
            print(f"{method}请求超时/连接失败 {url}：{str(e)}")
            return None
        except RequestException as e:
            print(f"{method}请求异常 {url}：{str(e)}")
            return None

    def update_headers(self, headers):
        """
        动态更新请求头（会合并，相同key覆盖）
        :param headers: 新请求头字典
        """
        if isinstance(headers, dict):
            self.session.headers.update(headers)
        else:
            print("请求头必须是字典类型！")

    def get_session(self):
        """获取当前session对象（用于特殊场景复用）"""
        return self.session

    def close(self):
        """关闭session，释放连接资源（扫描器退出前调用）"""
        if self.session:
            self.session.close()

