from .base import BaseScanner
from utils.http_client import HttpClient
from utils.logger import ScannerLogger
from config.settings import Config
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, parse_qsl, urljoin
import time

# SQL错误特征（用于报错型检测）
SQL_ERROR_SIGNATURES = [
    'syntax',
    'mysql',
    'unclosed',
    'error',
    'sql',
    'warning',
    'error',
]

class SQLInjectionScanner(BaseScanner):
    def __init__(self, http_client: HttpClient, logger: ScannerLogger, config: Config):
        super().__init__(http_client, logger, config)
        
        # 加载所有需要的payload类型
        self.sql_error_payloads = self.payloads.get_payloads('sql_injection', 'error_based')
        self.boolean_payloads = self.payloads.get_payloads('sql_injection', 'boolean_blind')
        self.time_delay_payloads = self.payloads.get_payloads('sql_injection', 'time_blind')
        self.union_payloads = self.payloads.get_payloads('sql_injection', 'union_based')

    
    def scan(self, target):
        """
        扫描目标 - 根据target类型调用不同的扫描函数
        
        参数:
            target: 目标URL（字符串）或目标信息（字典）
        
        返回:
            list: 发现的漏洞列表
        """
        if isinstance(target, str):
            # URL扫描
            return self.url_scan(target)
        elif isinstance(target, dict):
            # 表单扫描
            return self.form_scan(target)
        else:
            self.logger.error(f"不支持的目标类型: {type(target)}")
            return self.get_results()
    
    def url_scan(self, url):
        """
        URL扫描 - 四步走策略(报错注入、布尔盲注、时间盲注、联合查询)
        """
        self.logger.info(f"开始URL扫描: {url}")
        
        # 报错注入检测
        self.logger.info("第一步：进行报错注入检测...")
        result = self.test_error_based_url(url)
        if result and result['is_vuln']:
            self.record_vulnerability(result, url, 'get')
            return self.get_results()
        
        # 布尔盲注检测
        self.logger.info("第二步：进行布尔盲注检测...")
        result = self.test_boolean_based_url(url)
        if result and result['is_vuln']:
            self.record_vulnerability(result, url, 'get')
            return self.get_results()
        
        # 时间盲注检测
        self.logger.info("第三步：进行时间盲注检测...")
        result = self.test_time_based_url(url)
        if result and result['is_vuln']:
            self.record_vulnerability(result, url, 'get')
            return self.get_results()
        
        # 联合查询检测
        self.logger.info("第四步：进行联合查询检测...")
        result = self.test_union_based_url(url)
        if result and result['is_vuln']:
            self.record_vulnerability(result, url, 'get')
            return self.get_results()
        
        self.logger.info("未发现SQL注入漏洞")
        return self.get_results()
    
    def form_scan(self, form_info: dict):
        """
        表单扫描 - 四步走策略(报错注入、布尔盲注、时间盲注、联合查询)
        """
        self.logger.info("开始表单扫描...")
        
        # 提取表单信息
        target_url = form_info.get('url', '')
        action = form_info.get('action', target_url)
        method = form_info.get('method', 'get').lower()
        
        # 构建完整URL
        try:
            action_url = urljoin(target_url, action)
        except Exception:
            action_url = action
        
        self.logger.info(f"目标URL: {action_url}, 方法: {method}")
        
        # 构建表单数据
        if method == 'post':
            form_data = {}
            for inp in form_info.get('inputs', []):
                name = inp.get('name', '')
                if name:
                    form_data[name] = inp.get('value', '1')
            
            # 报错注入检测
            self.logger.info("第一步：进行报错注入检测...")
            result = self.test_error_based_form(action_url, form_data, method)
            if result and result['is_vuln']:
                self.record_vulnerability(result, action_url, method)
                return self.get_results()
            
            # 布尔盲注检测
            self.logger.info("第二步：进行布尔盲注检测...")
            result = self.test_boolean_based_form(action_url, form_data, method)
            if result and result['is_vuln']:
                self.record_vulnerability(result, action_url, method)
                return self.get_results()
            
            # 时间盲注检测
            self.logger.info("第三步：进行时间盲注检测...")
            result = self.test_time_based_form(action_url, form_data, method)
            if result and result['is_vuln']:
                self.record_vulnerability(result, action_url, method)
                return self.get_results()
            
            # 联合查询检测（仅对GET方法有效）
        
        else:  # GET方法
            params = {}
            for inp in form_info.get('inputs', []):
                name = inp.get('name', '')
                if name:
                    params[name] = inp.get('value', '1')
            
            # 构建带参数的URL
            if params:
                query_string = urlencode(params)
                full_url = target_url + ('?' if '?' not in target_url else '&') + query_string
                # 直接调用url_scan
                return self.url_scan(full_url)
            else:
                # 没有参数，直接测试URL
                return self.url_scan(target_url)
        
        self.logger.info("未发现SQL注入漏洞")
        return self.get_results()
    
    def record_vulnerability(self, result, url, method):
        """记录漏洞信息"""
        trigger_url = result.get('trigger_url', url)
        form_data = result.get('form_data', {})
        
        # 构建漏洞信息
        vuln_info = {
            'type': f"SQL Injection ({result['vuln_type']})",
            'url': trigger_url,
            'trigger_payload': result['payload'],
            'confidence': 'high',
            'method': method.upper()
        }
        
        # 根据方法类型构建不同的描述
        if method == 'get':
            vuln_info['description'] = f"检测到SQL注入漏洞(GET请求)，触发payload为：{result['payload']}，完整URL：{trigger_url}"
        elif method == 'post':
            # 对于POST请求，显示表单数据
            if form_data:
                form_info = ', '.join([f"{k}={v}" for k, v in form_data.items()])
                vuln_info['description'] = f"检测到SQL注入漏洞(POST请求)，触发payload为：{result['payload']}，目标URL：{trigger_url}，表单数据：{form_info}"
                vuln_info['form_data'] = form_data
            else:
                vuln_info['description'] = f"检测到SQL注入漏洞(POST请求)，触发payload为：{result['payload']}，目标URL：{trigger_url}"
        
        self.add_result(vuln_info)
    

    
    def test_error_based_url(self, url):
        """URL报错注入检测"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            # 如果没有参数，尝试添加测试参数
            test_url = url + ('?' if '?' not in url else '&') + 'id=1'
            return self.test_error_based_url(test_url)
        
        original_resp = self.client.get(url)
        if not original_resp:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
        
        for param, values in qs.items():
            original_value = values[0] if values else ''
            for payload in self.sql_error_payloads:
                # 两种测试方式：追加和替换
                test_values = [original_value + payload, payload]
                
                for test_value in test_values:
                    new_qs = qs.copy()
                    new_qs[param] = [test_value]
                    new_query = urlencode({k: v[0] for k, v in new_qs.items()}, doseq=True)
                    new_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    resp = self.client.get(new_url)
                    if resp and self.detect_error_in_response(original_resp, resp):
                        return {
                            'is_vuln': True,
                            'payload': payload,
                            'vuln_type': 'error-based',
                            'trigger_url': new_url
                        }
        
        return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
    
    def test_boolean_based_url(self, url):
        """URL布尔盲注检测"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
        
        # 获取正常响应
        normal_resp = self.client.get(url)
        if not normal_resp:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
        
        for param, values in qs.items():
            original_value = values[0] if values else ''
            
            # 尝试数字型和字符型payload
            for true_payload, false_payload in self.boolean_payloads:
                # True条件
                new_qs_true = qs.copy()
                new_qs_true[param] = [original_value + true_payload]
                new_query_true = urlencode({k: v[0] for k, v in new_qs_true.items()}, doseq=True)
                true_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query_true, parsed.fragment
                ))
                
                # False条件
                new_qs_false = qs.copy()
                new_qs_false[param] = [original_value + false_payload]
                new_query_false = urlencode({k: v[0] for k, v in new_qs_false.items()}, doseq=True)
                false_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query_false, parsed.fragment
                ))
                
                true_resp = self.client.get(true_url)
                false_resp = self.client.get(false_url)
                
                if true_resp and false_resp and self.detect_boolean_difference(true_resp, false_resp):
                    return {
                        'is_vuln': True,
                        'payload': f"True: {true_payload}, False: {false_payload}",
                        'vuln_type': 'boolean-based',
                        'trigger_url': true_url  # 使用true条件的URL
                    }
        
        return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
    
    def test_time_based_url(self, url):
        """URL时间盲注检测"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
        
        # 获取基准响应时间
        baseline_times = []
        for _ in range(2):
            try:
                start = time.time()
                resp = self.client.get(url, timeout=10)
                if resp:
                    baseline_times.append(time.time() - start)
            except:
                baseline_times.append(0)
        
        if not baseline_times:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
        
        baseline = sum(baseline_times) / len(baseline_times)
        
        # 设置动态阈值
        if baseline < 1.0:
            threshold = baseline + 2.0
        else:
            threshold = baseline * 2
        
        for param, values in qs.items():
            original_value = values[0] if values else ''
            for payload in self.time_delay_payloads:
                new_qs = qs.copy()
                new_qs[param] = [str(original_value) + payload]
                new_query = urlencode({k: v[0] for k, v in new_qs.items()})
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                try:
                    start = time.time()
                    resp = self.client.get(new_url, timeout=10)
                    elapsed = time.time() - start
                    
                    if elapsed > threshold and resp:
                        return {
                            'is_vuln': True,
                            'payload': payload,
                            'vuln_type': 'time-based',
                            'trigger_url': new_url
                        }
                except Exception as e:
                    # 如果超时，也认为是时间延迟
                    if "timeout" in str(e).lower():
                        return {
                            'is_vuln': True,
                            'payload': payload,
                            'vuln_type': 'time-based',
                            'trigger_url': new_url
                        }
                    continue
        
        return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
    
    def test_union_based_url(self, url):
        """URL联合查询检测"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
        
        # 先探测列数
        column_count = self.detect_column_count_url(url)
        if column_count <= 0:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
        
        # 构建UNION SELECT payload
        union_payload = self.build_union_payload(column_count)
        
        for param, values in qs.items():
            original_value = values[0] if values else ''
            
            new_qs = qs.copy()
            new_qs[param] = [original_value + union_payload]
            new_query = urlencode({k: v[0] for k, v in new_qs.items()}, doseq=True)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            resp = self.client.get(new_url)
            if resp and self.detect_union_response(resp):
                return {
                    'is_vuln': True,
                    'payload': union_payload,
                    'vuln_type': 'union-based',
                    'trigger_url': new_url
                }
        
        return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': ''}
    
    def detect_column_count_url(self, url):
        """探测URL参数列数"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        
        if not qs:
            return 0
        
        param = list(qs.keys())[0]
        original_value = qs[param][0] if qs[param] else ''
        
        # 测试常见的列数
        for count in [3, 5, 10, 20, 30]:
            for payload_template in self.union_payloads:
                order_payload = payload_template.format(count)
                
                new_qs = qs.copy()
                new_qs[param] = [original_value + order_payload]
                new_query = urlencode({k: v[0] for k, v in new_qs.items()}, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                resp = self.client.get(test_url)
                if resp and resp.status_code >= 500:
                    # 这个列数可能太大，测试更小的数字
                    if count == 3:
                        # 测试2列
                        test_payload = payload_template.format(2)
                        new_qs[param] = [original_value + test_payload]
                        new_query = urlencode({k: v[0] for k, v in new_qs.items()}, doseq=True)
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))
                        
                        test_resp = self.client.get(test_url)
                        if test_resp and test_resp.status_code < 500:
                            return 2
                    continue
                else:
                    # 这个列数可能有效，测试count+1
                    next_payload = payload_template.format(count + 1)
                    new_qs[param] = [original_value + next_payload]
                    new_query = urlencode({k: v[0] for k, v in new_qs.items()}, doseq=True)
                    next_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    next_resp = self.client.get(next_url)
                    if next_resp and next_resp.status_code >= 500:
                        # count成功，count+1失败，说明列数就是count
                        return count
        
        return 0
    
    
    def test_error_based_form(self, url, form_data, method):
        """表单报错注入检测"""
        if not form_data:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
        
        if method == 'get':
            original_resp = self.client.get(url, params=form_data)
        else:
            original_resp = self.client.post(url, data=form_data)
        
        if not original_resp:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
        
        for param, value in form_data.items():
            for payload in self.sql_error_payloads:
                # 两种测试方式：追加和替换
                test_values = [str(value) + payload, payload]
                
                for test_value in test_values:
                    new_form = form_data.copy()
                    new_form[param] = test_value
                    
                    if method == 'get':
                        resp = self.client.get(url, params=new_form)
                    else:
                        resp = self.client.post(url, data=new_form)
                    
                    if resp and self.detect_error_in_response(original_resp, resp):
                        return {
                            'is_vuln': True,
                            'payload': payload,
                            'vuln_type': 'error-based',
                            'trigger_url': url,
                            'form_data': new_form
                        }
        
        return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
    
    def test_boolean_based_form(self, url, form_data, method):
        """表单布尔盲注检测"""
        if not form_data:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
        
        # 获取正常响应
        if method == 'get':
            normal_resp = self.client.get(url, params=form_data)
        else:
            normal_resp = self.client.post(url, data=form_data)
        
        if not normal_resp:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
        
        for param, value in form_data.items():
            for true_payload, false_payload in self.boolean_payloads:
                # True条件
                new_form_true = form_data.copy()
                new_form_true[param] = str(value) + true_payload
                
                # False条件
                new_form_false = form_data.copy()
                new_form_false[param] = str(value) + false_payload
                
                if method == 'get':
                    true_resp = self.client.get(url, params=new_form_true)
                    false_resp = self.client.get(url, params=new_form_false)
                else:
                    true_resp = self.client.post(url, data=new_form_true)
                    false_resp = self.client.post(url, data=new_form_false)
                
                if true_resp and false_resp and self.detect_boolean_difference(true_resp, false_resp):
                    return {
                        'is_vuln': True,
                        'payload': f"True: {true_payload}, False: {false_payload}",
                        'vuln_type': 'boolean-based',
                        'trigger_url': url,
                        'form_data': new_form_true
                    }
        
        return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
    
    def test_time_based_form(self, url, form_data, method):
        """表单时间盲注检测"""
        if not form_data:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
        
        # 获取基准响应时间
        baseline_times = []
        for _ in range(2):
            try:
                start = time.time()
                if method == 'get':
                    resp = self.client.get(url, params=form_data, timeout=10)
                else:
                    resp = self.client.post(url, data=form_data, timeout=10)
                
                if resp:
                    baseline_times.append(time.time() - start)
            except:
                baseline_times.append(0)
        
        if not baseline_times:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
        
        baseline = sum(baseline_times) / len(baseline_times)
        
        # 设置动态阈值
        if baseline < 1.0:
            threshold = baseline + 3.0  
        else:
            threshold = baseline * 2.5
        
        for param, value in form_data.items():
            for payload in self.time_delay_payloads:
                new_form = form_data.copy()
                new_form[param] = str(value) + payload
                
                try:
                    start = time.time()
                    if method == 'get':
                        resp = self.client.get(url, params=new_form, timeout=10)
                    else:
                        resp = self.client.post(url, data=new_form, timeout=10)
                    
                    elapsed = time.time() - start
                    
                    if elapsed > threshold and resp:
                        return {
                            'is_vuln': True,
                            'payload': payload,
                            'vuln_type': 'time-based',
                            'trigger_url': url,
                            'form_data': new_form
                        }
                except Exception as e:
                    # 如果超时，也认为是时间延迟
                    if "timeout" in str(e).lower():
                        return {
                            'is_vuln': True,
                            'payload': payload,
                            'vuln_type': 'time-based',
                            'trigger_url': url,
                            'form_data': new_form
                        }
                    continue
        
        return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
    
    def test_union_based_form(self, url, form_data, method):
        """表单联合查询检测（仅适用于GET方法）"""
        if method != 'get' or not form_data:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
        
        # 先探测列数
        column_count = self.detect_column_count_form(url, form_data, method)
        if column_count <= 0:
            return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
        
        # 构建UNION SELECT payload
        union_payload = self.build_union_payload(column_count)
        
        for param, value in form_data.items():
            new_form = form_data.copy()
            new_form[param] = str(value) + union_payload
            
            resp = self.client.get(url, params=new_form)
            if resp and self.detect_union_response(resp):
                return {
                    'is_vuln': True,
                    'payload': union_payload,
                    'vuln_type': 'union-based',
                    'trigger_url': url,
                    'form_data': new_form
                }
        
        return {'is_vuln': False, 'payload': '', 'vuln_type': '', 'trigger_url': '', 'form_data': {}}
    
    def detect_column_count_form(self, url, form_data, method):
        """探测表单参数列数"""
        if method != 'get' or not form_data:
            return 0
        
        param = list(form_data.keys())[0]
        original_value = form_data[param]
        
        # 测试常见的列数
        for count in [3, 5, 10, 20, 30]:
            for payload_template in self.union_payloads:
                order_payload = payload_template.format(count)
                
                new_form = form_data.copy()
                new_form[param] = str(original_value) + order_payload
                
                resp = self.client.get(url, params=new_form)
                if resp and resp.status_code >= 500:
                    # 这个列数可能太大，测试更小的数字
                    if count == 3:
                        # 测试2列
                        test_payload = payload_template.format(2)
                        new_form[param] = str(original_value) + test_payload
                        test_resp = self.client.get(url, params=new_form)
                        if test_resp and test_resp.status_code < 500:
                            return 2
                    continue
                else:
                    # 这个列数可能有效，测试count+1
                    next_payload = payload_template.format(count + 1)
                    new_form[param] = str(original_value) + next_payload
                    next_resp = self.client.get(url, params=new_form)
                    if next_resp and next_resp.status_code >= 500:
                        # count成功，count+1失败，说明列数就是count
                        return count
        
        return 0
    

    
    def detect_error_in_response(self, original_response, test_response):
        """检测响应中是否包含SQL错误"""
        if not original_response or not test_response:
            return False
        
        # 状态码从200变为500或从正常变为错误
        if original_response.status_code in [200, 302] and test_response.status_code >= 500:
            return True
        
        # 响应文本包含SQL错误特征
        text = test_response.text.lower()
        for sig in SQL_ERROR_SIGNATURES:
            if sig in text:
                return True
        
        # 响应文本长度差异过大
        orig_len = len(original_response.text or '')
        test_len = len(test_response.text or '')
        if orig_len > 0 and abs(test_len - orig_len) > max(50, orig_len * 0.1):
            return True
        
        # 响应内容明显不同（比如出现了错误页面）
        orig_text = original_response.text or ''
        test_text = test_response.text or ''
        if 'error' in test_text.lower() and 'error' not in orig_text.lower():
            return True
        
        return False
    
    def detect_boolean_difference(self, response1, response2):
        """检测两个响应的布尔差异"""
        # 长度差异 > 10%
        len1 = len(response1.text or '')
        len2 = len(response2.text or '')
        if len1 > 0 and abs(len1 - len2) / len1 > 0.1:
            return True
        
        # 状态码不同
        if response1.status_code != response2.status_code:
            return True
        
        # 关键词差异
        keywords = ['success', 'failed', 'error', 'not found', '不存在', '失败', '成功', '错误']
        
        text1 = (response1.text or '').lower()
        text2 = (response2.text or '').lower()
        
        keyword_differences = 0
        for keyword in keywords:
            in_resp1 = keyword in text1
            in_resp2 = keyword in text2
            if in_resp1 != in_resp2:
                keyword_differences += 1
        
        # 如果关键词差异超过2个，认为有显著差异
        if keyword_differences >= 2:
            return True
        
        # 检查重定向差异
        if len(response1.history) != len(response2.history):
            return True
        
        return False
    
    def detect_union_response(self, response):
        """检测联合查询响应"""
        if not response:
            return False
        
        # 检查是否回显了数字
        for i in range(1, 11):  # 检查1-10
            if str(i) in response.text:
                return True
        
        # 检查响应长度是否显著增加
        return False
    
    def build_union_payload(self, column_count):
        """构建UNION SELECT payload"""
        columns = [str(i) for i in range(1, column_count + 1)]
        union_select = " UNION SELECT " + ",".join(columns) + "--"
        return union_select