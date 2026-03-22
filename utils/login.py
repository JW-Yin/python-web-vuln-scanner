from utils.http_client import HttpClient
from utils.logger import ScannerLogger
from config.settings import Config
from core.crawler import Crawler
from urllib.parse import urljoin

class LoginHelper:
    def __init__(self, client: HttpClient, config: Config, logger: ScannerLogger):
        self.client = client
        self.config = config
        self.logger = logger
        self.crawler = Crawler(client, logger, config)
        self.logger.info("登录辅助模块初始化完成")


    def login_dvwa(self):
        """
        尝试登录DVWA以获取会话
        """
        # 未登录会被自动重定向到登陆页面，先爬取登陆页面获取表单URL，然后登录即可
        base_url = self.config.get('scanner', 'url')
        resp = self.client.get(base_url)

        if not resp:
            self.logger.warning('获取登录页面失败，无法登录DVWA')
            return False

        forms = self.crawler.discover_forms(resp.text or '', getattr(resp, 'url', base_url)) or []
        login_url = None
        data = {}
        for form in forms:
            action = form.get('action', '') or ''
            if 'login' in action.lower() or 'action=login' in action.lower():
                login_url = urljoin(getattr(resp, 'url', base_url), action)
                self.logger.info(f'发现DVWA登录表单，登录URL: {login_url}')
                for input_info in form.get('inputs', []):
                    name = input_info.get('name')
                    if not name:
                        continue
                    data[name] = input_info.get('value', '')
                break
        if not login_url:
            self.logger.warning('未找到DVWA登录表单，无法登录')
            return False

        try:
            data['username'] = self.config.get('auth', 'username')
            data['password'] = self.config.get('auth', 'password')
        except Exception:
            self.logger.warning('配置中缺少 auth.username/auth.password')
            return False

        self.logger.info('尝试登录DVWA以获取会话…')
        login_resp = self.client.post(login_url, data=data)

        if not login_resp:
            self.logger.warning('登录请求失败（无响应）')
            return False

        body = (login_resp.text or '').lower()
        if 'failed' not in body and ('logout' in body or 'welcome' in body or 'login' not in body):
            self.logger.info('DVWA登录成功')
            try:
                self.set_dvwa_security()
            except Exception:
                self.logger.debug('设置DVWA安全级别时发生异常', exc_info=True)
            return True

        self.logger.warning('DVWA登录失败')
        return False
    
    def set_dvwa_security(self):
        """
        设置DVWA安全级别
        """
        security_page = "http://127.0.0.1/dvwa/security.php"
        resp = self.client.get(security_page)
        if not resp:
            self.logger.warning('无法访问 DVWA 安全设置页面')
            return False

        forms = self.crawler.discover_forms(resp.text or '', getattr(resp, 'url', security_page)) or []
        chosen_form = None
        for form in forms:
            action = (form.get('action') or '').lower()
            inputs = form.get('inputs', [])
            input_names = [i.get('name', '').lower() for i in inputs if i.get('name')]
            if 'security' in action or 'security.php' in action or 'security' in input_names:
                chosen_form = form
                break

        target_url = security_page
        data = {}
        method = 'post'
        if chosen_form:
            action = chosen_form.get('action') or ''
            target_url = urljoin(getattr(resp, 'url', security_page), action)
            method = (chosen_form.get('method') or 'post').lower()
            self.logger.info(f'发现DVWA安全级别设置表单: {target_url} (method={method})')
            for input_info in chosen_form.get('inputs', []):
                name = input_info.get('name')
                if not name:
                    continue
                data[name] = input_info.get('value', '')

        try:
            level = self.config.get('dvwa', 'security_level')
        except Exception:
            try:
                level = self.config.get('scanner', 'dvwa_security_level')
            except Exception:
                level = 'low'

        data['security'] = level
        try:
            self.logger.debug(f'提交安全设置到 {target_url}，method={method}，字段: {list(data.keys())}')
        except Exception:
            pass

        if method == 'get':
            resp2 = self.client.get(target_url, params=data)
        else:
            resp2 = self.client.post(target_url, data=data)
        if not resp2:
            self.logger.warning('提交安全级别设置失败')
            return False

        if not resp2:
            self.logger.warning('提交安全级别设置失败')
            return False


        follow = self.client.get(security_page)
        page_text = (follow.text or '').lower() if follow else (resp2.text or '').lower()


        if f'value="{level}"' in page_text and 'selected' in page_text:
            self.logger.info(f'DVWA安全级别设置为{level}')
            return True

        if 'security level set to' in page_text and level in page_text:
            self.logger.info(f'DVWA安全级别设置为{level}')
            return True

        self.logger.warning('未能设置DVWA安全级别')
        return False
    