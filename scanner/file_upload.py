from .base import BaseScanner
from utils import payloads
import re
import os
from urllib.parse import urljoin, urlparse
import mimetypes

class FileUploadScanner(BaseScanner):
    def __init__(self, http_client, logger, config):
        super().__init__(http_client, logger, config)
        self.upload_payloads = self.payloads.get_payloads('file_upload')
        if not isinstance(self.upload_payloads, list):
            self.upload_payloads = []
        
    def scan(self, target):
        """
        扫描文件上传漏洞
        target: 包含表单信息的字典或URL字符串
        """
        vuln_info = None
        target_url = ""
        method = "post"
        
        if isinstance(target, str):
            target_url = target
            method = "get"
            # 查找页面中的上传表单
            forms = self.find_upload_forms(target_url)
            for form_info in forms:
                result = self.test_file_upload(form_info)
                if result and result.get('is_vuln'):
                    vuln_info = result
                    vuln_info['method'] = form_info.get('method', 'post').upper()
                    vuln_info['trigger_url'] = form_info.get('action', target_url)
                    break
                    
        elif isinstance(target, dict):
            target_url = target.get('url', '')
            method = target.get('method', 'get').lower()
            action = target.get('action') or target_url
            try:
                action_url = urljoin(target_url, action)
            except Exception:
                action_url = action

            # 检查是否有文件上传字段
            inputs = target.get('inputs', [])
            
            # 构建表单数据
            form_data = {}
            file_fields = []
            for inp in inputs:
                name = inp.get('name')
                if not name:
                    continue
                    
                inp_type = inp.get('type', '').lower()
                value = inp.get('value', '')
                
                if inp_type == 'file' or 'file' in name.lower():
                    file_fields.append(name)
                else:
                    form_data[name] = value

            if file_fields:
                # 有文件上传字段，测试文件上传漏洞
                form_info = {
                    'action': action_url,
                    'method': method,
                    'form_data': form_data,
                    'file_fields': file_fields
                }
                
                result = self.test_file_upload(form_info)
                if result and result.get('is_vuln'):
                    vuln_info = result
                    vuln_info['method'] = method.upper()
                    vuln_info['trigger_url'] = action_url
            else:
                # 没有文件上传字段，直接返回无漏洞
                return self.get_results()
        
        # 检测到漏洞则记录结果
        if vuln_info and vuln_info.get('is_vuln'):
            method = vuln_info.get('method', method)
            trigger_url = vuln_info.get('trigger_url', '')
            form_data = vuln_info.get('form_data', {})
            payload = vuln_info.get('payload', '')
            file_url = vuln_info.get('file_url', '')
            vuln_type = vuln_info.get('vuln_type', 'File Upload')
            bypass_type = vuln_info.get('bypass_type', '')
            confidence = vuln_info.get('confidence', 'medium')
            
            # 构建结果信息
            result_info = {
                'type': vuln_type,
                'url': trigger_url,
                'trigger_payload': payload,
                'confidence': confidence,
                'method': method.upper()
            }
            
            # 添加漏洞详细信息
            description = f"检测到{vuln_type}漏洞"
            if bypass_type:
                description += f"（{bypass_type}绕过）"
            description += f"({method}请求)"
            
            # 添加目标URL
            description += f"，目标URL：{trigger_url}"
            
            # 添加触发payload
            description += f"，触发payload：{payload}"
            
            # 添加上传的文件URL（如果存在）
            if file_url:
                description += f"，上传文件URL：{file_url}"
                result_info['file_url'] = file_url
            
            # 添加表单数据（如果有）
            if form_data:
                filtered_form_data = {k: v for k, v in form_data.items() 
                                    if k.lower() not in ['user_token', 'csrf_token', 'token']}
                if filtered_form_data:
                    form_info = ', '.join([f"{k}={v}" for k, v in filtered_form_data.items()])
                    description += f"，表单数据：{form_info}"
                    result_info['form_data'] = filtered_form_data
            
            result_info['description'] = description
            
            # 添加绕过类型（如果有）
            if bypass_type:
                result_info['bypass_type'] = bypass_type
            
            self.add_result(result_info)
        
        return self.get_results()

    def find_upload_forms(self, url):
        """查找页面中的文件上传表单"""
        resp = self.client.get(url)
        forms = []
        if not resp:
            return forms
        
        html = resp.text or ''
        
        # 查找所有表单
        form_pattern = r'<form[^>]*action=["\']?([^"\'\s>]*)["\']?[^>]*method=["\']?([^"\'\s>]*)["\']?[^>]*>'
        form_matches = re.findall(form_pattern, html, re.IGNORECASE)
        
        for action, method in form_matches:
            # 检查表单是否包含文件上传字段
            form_content_pattern = r'<form[^>]*>.*?</form>'
            form_content_matches = re.findall(form_content_pattern, html, re.IGNORECASE | re.DOTALL)
            
            for form_content in form_content_matches:
                if 'type="file"' in form_content or "type='file'" in form_content:
                    # 解析表单字段
                    fields = []
                    file_fields = []
                    
                    # 查找input字段
                    input_pattern = r'<input[^>]*name=["\']?([^"\'\s>]*)["\']?[^>]*type=["\']?([^"\'\s>]*)["\']?[^>]*>'
                    input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
                    
                    for name, inp_type in input_matches:
                        if not name:
                            continue
                            
                        inp_type = inp_type.lower()
                        if inp_type == 'file' or 'file' in name.lower():
                            file_fields.append(name)
                        else:
                            # 尝试获取value
                            value_pattern = rf'<input[^>]*name=["\']?{re.escape(name)}["\']?[^>]*value=["\']?([^"\'\s>]*)["\']?[^>]*>'
                            value_match = re.search(value_pattern, form_content, re.IGNORECASE)
                            value = value_match.group(1) if value_match else ''
                            fields.append({'name': name, 'type': inp_type, 'value': value})
                    
                    # 构建完整的action URL
                    full_action = urljoin(url, action) if action else url
                    method = method.lower() if method else 'post'
                    
                    forms.append({
                        'action': full_action,
                        'method': method,
                        'fields': fields,
                        'file_fields': file_fields
                    })
        
        return forms

    def test_file_upload(self, form_info):
        """
        测试文件上传漏洞
        
        返回: {'is_vuln': bool, 'payload': str, 'vuln_type': str, 'file_url': str, 
               'bypass_type': str, 'confidence': str, 'form_data': dict}
        """
        action = form_info.get('action')
        method = form_info.get('method', 'post')
        form_data = form_info.get('form_data', {})
        file_fields = form_info.get('file_fields', [])
        
        if not action or not file_fields:
            return {'is_vuln': False}
        
        # 首先测试正常的文件上传，建立基线
        test_file = self._create_test_file('test.txt', 'This is a test file')
        files = {}
        for field in file_fields:
            files[field] = test_file
        
        # 发送请求
        if method.lower() == 'post':
            resp = self.client.post(action, data=form_data, files=files)
        else:
            resp = self.client.request(method, action, data=form_data, files=files)
        
        if not resp:
            return {'is_vuln': False}
        
        # 1. 测试基础文件上传漏洞（使用危险扩展名）
        result = self._test_basic_upload(action, method, form_data, file_fields)
        if result.get('is_vuln'):
            return result
        
        # 2. 测试扩展名绕过
        result = self._test_extension_bypass(action, method, form_data, file_fields)
        if result.get('is_vuln'):
            return result
        
        # 3. 测试Content-Type绕过
        result = self._test_content_type_bypass(action, method, form_data, file_fields)
        if result.get('is_vuln'):
            return result
        
        # 4. 测试Magic Bytes绕过
        result = self._test_magic_bytes_bypass(action, method, form_data, file_fields)
        if result.get('is_vuln'):
            return result
        
        # 5. 测试其他payload
        result = self._test_other_payloads(action, method, form_data, file_fields)
        if result.get('is_vuln'):
            return result
        
        return {'is_vuln': False}

    def _test_basic_upload(self, action, method, form_data, file_fields):
        """测试基础文件上传漏洞"""
        # 使用危险扩展名测试
        dangerous_extensions = ['.php', '.php5', '.phtml', '.php7', '.phar', '.jsp', '.asp', '.aspx']
        
        for ext in dangerous_extensions:
            filename = f"shell{ext}"
            file_content = b'<?php echo "Basic Upload Test"; ?>'
            files = {}
            for field in file_fields:
                files[field] = (filename, file_content, 'application/octet-stream')
            
            if method.lower() == 'post':
                resp = self.client.post(action, data=form_data, files=files)
            else:
                resp = self.client.request(method, action, data=form_data, files=files)
            
            if resp and self._check_upload_success(resp, filename, file_content):
                file_url = self._extract_file_url(resp, action)
                return {
                    'is_vuln': True,
                    'vuln_type': 'File Upload',
                    'payload': filename,
                    'file_url': file_url,
                    'bypass_type': 'Basic',
                    'confidence': 'high',
                    'form_data': form_data
                }
        
        return {'is_vuln': False}

    def _test_extension_bypass(self, action, method, form_data, file_fields):
        """测试扩展名绕过"""
        # 测试payloads.json中的扩展名绕过payload
        for payload in self.upload_payloads:
            if not isinstance(payload, str):
                continue
                
            # 创建文件内容
            if payload.endswith('.php') or 'php' in payload.lower():
                file_content = b'<?php echo "Extension Bypass Test"; ?>'
            else:
                file_content = b'Extension Bypass Test Content'
            
            files = {}
            for field in file_fields:
                files[field] = (payload, file_content, 'application/octet-stream')
            
            if method.lower() == 'post':
                resp = self.client.post(action, data=form_data, files=files)
            else:
                resp = self.client.request(method, action, data=form_data, files=files)
            
            if resp and self._check_upload_success(resp, payload, file_content):
                file_url = self._extract_file_url(resp, action)
                return {
                    'is_vuln': True,
                    'vuln_type': 'File Upload',
                    'payload': payload,
                    'file_url': file_url,
                    'bypass_type': 'Extension Bypass',
                    'confidence': 'high',
                    'form_data': form_data
                }
        
        return {'is_vuln': False}

    def _test_content_type_bypass(self, action, method, form_data, file_fields):
        """测试Content-Type绕过"""
        # 使用PHP文件但设置为图片Content-Type
        test_cases = [
            ('shell.php', b'<?php echo "Content-Type Bypass Test"; ?>', 'image/jpeg'),
            ('shell.php', b'<?php echo "Content-Type Bypass Test"; ?>', 'image/png'),
            ('shell.php', b'<?php echo "Content-Type Bypass Test"; ?>', 'image/gif'),
            ('shell.php', b'<?php echo "Content-Type Bypass Test"; ?>', 'text/plain'),
        ]
        
        for filename, content, content_type in test_cases:
            files = {}
            for field in file_fields:
                files[field] = (filename, content, content_type)
            
            if method.lower() == 'post':
                resp = self.client.post(action, data=form_data, files=files)
            else:
                resp = self.client.request(method, action, data=form_data, files=files)
            
            if resp and self._check_upload_success(resp, filename, content):
                file_url = self._extract_file_url(resp, action)
                return {
                    'is_vuln': True,
                    'vuln_type': 'File Upload',
                    'payload': filename,
                    'file_url': file_url,
                    'bypass_type': f'Content-Type Bypass ({content_type})',
                    'confidence': 'medium',
                    'form_data': form_data
                }
        
        return {'is_vuln': False}

    def _test_magic_bytes_bypass(self, action, method, form_data, file_fields):
        """测试Magic Bytes绕过"""
        # 不同文件的Magic Bytes
        magic_bytes = {
            'png': b'\x89PNG\r\n\x1a\n',
            'jpg': b'\xff\xd8\xff\xe0',
            'gif': b'GIF89a',
        }
        
        for file_type, magic in magic_bytes.items():
            # 创建带有Magic Bytes的PHP文件
            content = magic + b'<?php echo "Magic Bytes Bypass Test"; ?>'
            filename = f'shell.{file_type}'
            
            files = {}
            for field in file_fields:
                files[field] = (filename, content, f'image/{file_type}')
            
            if method.lower() == 'post':
                resp = self.client.post(action, data=form_data, files=files)
            else:
                resp = self.client.request(method, action, data=form_data, files=files)
            
            if resp and self._check_upload_success(resp, filename, content):
                file_url = self._extract_file_url(resp, action)
                return {
                    'is_vuln': True,
                    'vuln_type': 'File Upload',
                    'payload': filename,
                    'file_url': file_url,
                    'bypass_type': f'Magic Bytes Bypass ({file_type.upper()})',
                    'confidence': 'medium',
                    'form_data': form_data
                }
        
        return {'is_vuln': False}

    def _test_other_payloads(self, action, method, form_data, file_fields):
        """测试其他payload"""
        # 测试路径遍历payload
        traversal_payloads = ['../shell.php', '../../shell.php', '../../../shell.php']
        
        for payload in traversal_payloads:
            file_content = b'<?php echo "Path Traversal Test"; ?>'
            files = {}
            for field in file_fields:
                files[field] = (payload, file_content, 'application/octet-stream')
            
            if method.lower() == 'post':
                resp = self.client.post(action, data=form_data, files=files)
            else:
                resp = self.client.request(method, action, data=form_data, files=files)
            
            if resp and self._check_upload_success(resp, payload, file_content):
                file_url = self._extract_file_url(resp, action)
                return {
                    'is_vuln': True,
                    'vuln_type': 'File Upload',
                    'payload': payload,
                    'file_url': file_url,
                    'bypass_type': 'Path Traversal',
                    'confidence': 'high',
                    'form_data': form_data
                }
        
        return {'is_vuln': False}

    def _create_test_file(self, filename, content):
        """创建测试文件"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        
        # 尝试猜测MIME类型
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        return (filename, content, mime_type)

    def _check_upload_success(self, response, filename, file_content):
        """检查文件是否上传成功"""
        if not response:
            return False
        
        text = response.text or ''
        
        # 检查上传成功的标志
        success_indicators = [
            'upload', 'success', 'file uploaded', '上传成功', 
            filename, 'php', '<?php'
        ]
        
        for indicator in success_indicators:
            if indicator.lower() in text.lower():
                return True
        
        # 检查文件内容是否出现在响应中
        if isinstance(file_content, bytes):
            file_content_str = file_content.decode('utf-8', errors='ignore')
        else:
            file_content_str = str(file_content)
        
        if file_content_str in text:
            return True
        
        # 检查状态码
        if response.status_code in [200, 201, 302]:
            # 进一步检查Location头或重定向
            if response.headers.get('Location'):
                return True
        
        return False

    def _extract_file_url(self, response, base_url):
        """从响应中提取文件URL"""
        if not response:
            return None
        
        # 从响应文本中提取URL
        text = response.text or ''
        url_patterns = [
            r'href=["\']([^"\']+\.(?:php|jsp|asp|aspx|txt))["\']',
            r'src=["\']([^"\']+\.(?:php|jsp|asp|aspx|txt))["\']',
            r'url\(["\']?([^"\'\)]+\.(?:php|jsp|asp|aspx|txt))["\']?\)',
            r'File: <a[^>]*href=["\']([^"\']+)["\']',
            r'下载[^<]*<a[^>]*href=["\']([^"\']+)["\']',
            r'download[^<]*<a[^>]*href=["\']([^"\']+)["\']'
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # 构建完整URL
                if match.startswith(('http://', 'https://')):
                    return match
                else:
                    return urljoin(base_url, match)
        
        # 检查Location头
        location = response.headers.get('Location')
        if location:
            if location.startswith(('http://', 'https://')):
                return location
            else:
                return urljoin(base_url, location)
        
        # 如果都没有找到，返回上传的action URL
        return base_url

    def verify_upload(self, file_url):
        """验证上传的文件是否可以访问"""
        if not file_url:
            return False
        
        resp = self.client.get(file_url)
        if not resp:
            return False
        
        # 检查响应中是否包含我们的测试标记
        test_markers = [
            'Basic Upload Test',
            'Extension Bypass Test',
            'Content-Type Bypass Test',
            'Magic Bytes Bypass Test',
            'Path Traversal Test',
            '<?php'
        ]
        
        text = resp.text or ''
        for marker in test_markers:
            if marker in text:
                return True
        
        # 检查状态码
        return resp.status_code == 200