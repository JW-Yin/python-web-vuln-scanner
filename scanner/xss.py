from .base import BaseScanner
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
import re
import time
import random

class XSSScanner(BaseScanner):
    def __init__(self, http_client, logger, config):
        super().__init__(http_client, logger, config)
        px = self.payloads.get_payloads('xss')
        if isinstance(px, dict):
            self.reflected_payloads = px.get('reflected', [])
            self.stored_payloads = px.get('stored', [])
        else:
            self.reflected_payloads = []
            self.stored_payloads = []
        
    def scan(self, target):
        """
        扫描XSS漏洞
        支持:
          - 反射型XSS
          - 存储型XSS
          - DOM型XSS（基础检测）
        """
        vuln_info = None
        target_url = ""
        method = "get"
        
        if isinstance(target, str):
            target_url = target
            method = "get"
            
            # 检查是否有查询参数
            parsed = urlparse(target_url)
            qs = parse_qs(parsed.query)
            
            if qs:
                # 有查询参数，测试反射型XSS
                for param, values in qs.items():
                    original_value = values[0] if values else ''
                    for payload in self.reflected_payloads:
                        # 只测试真正的XSS payload
                        if not self._is_xss_payload(payload):
                            continue
                            
                        result = self.test_reflected_xss(target_url, param, payload)
                        if result and result.get('is_vuln'):
                            vuln_info = result
                            vuln_info['method'] = 'get'
                            break
                    if vuln_info:
                        break
            else:
                # 没有查询参数，只测试DOM型XSS，不自动添加参数
                result = self.test_dom_xss(target_url)
                if result and result.get('is_vuln'):
                    vuln_info = result
                    vuln_info['method'] = 'get'
                    
        elif isinstance(target, dict):
            target_url = target.get('url', '')
            method = target.get('method', 'get').lower()
            action = target.get('action') or target_url
            try:
                from urllib.parse import urljoin
                action_url = urljoin(target_url, action)
            except Exception:
                action_url = action

            # 构建表单数据
            inputs = target.get('inputs', [])
            form_data = {}
            for inp in inputs:
                name = inp.get('name')
                if not name:
                    continue
                form_data[name] = inp.get('value') if inp.get('value') is not None else ''

            if method == 'post':
                # 先测试存储型XSS
                for payload in self.stored_payloads:
                    # 只测试真正的XSS payload
                    if not self._is_xss_payload(payload):
                        continue
                        
                    result = self.test_stored_xss(action_url, form_data, payload)
                    if result and result.get('is_vuln'):
                        vuln_info = result
                        vuln_info['method'] = 'post'
                        vuln_info['trigger_url'] = action_url
                        break
                
                # 如果没有找到存储型XSS，测试反射型XSS（POST参数反射）
                if not vuln_info:
                    for param, value in form_data.items():
                        # 跳过按钮、提交等非文本字段
                        input_type = None
                        for inp in inputs:
                            if inp.get('name') == param:
                                input_type = (inp.get('type') or '').lower()
                                break
                        
                        if input_type in ['submit', 'button', 'hidden', 'password']:
                            continue
                            
                        for payload in self.reflected_payloads:
                            # 只测试真正的XSS payload
                            if not self._is_xss_payload(payload):
                                continue
                                
                            result = self.test_post_reflected_xss(action_url, form_data, param, payload)
                            if result and result.get('is_vuln'):
                                vuln_info = result
                                vuln_info['method'] = 'post'
                                break
                        if vuln_info:
                            break
            else:
                # GET表单：测试反射型XSS
                testable_params = []
                for inp in inputs:
                    t = (inp.get('type') or '').lower()
                    name = inp.get('name')
                    if not name:
                        continue
                    if t in ('hidden', 'submit', 'button', 'password'):
                        continue
                    testable_params.append(name)

                for param in testable_params:
                    for payload in self.reflected_payloads:
                        # 只测试真正的XSS payload
                        if not self._is_xss_payload(payload):
                            continue
                            
                        result = self.test_reflected_xss(action_url, param, payload, extra_params=form_data)
                        if result and result.get('is_vuln'):
                            vuln_info = result
                            vuln_info['method'] = 'get'
                            break
                    if vuln_info:
                        break
        
        # 检测到漏洞则记录结果
        if vuln_info and vuln_info.get('is_vuln'):
            method = vuln_info.get('method', method)
            trigger_url = vuln_info.get('trigger_url', '')
            form_data = vuln_info.get('form_data', {})
            param = vuln_info.get('param', '')
            payload = vuln_info.get('payload', '')
            vuln_type = vuln_info.get('vuln_type', 'Reflected XSS')
            confidence = vuln_info.get('confidence', 'medium')
            
            # 构建结果信息
            result_info = {
                'type': vuln_type,
                'url': trigger_url,
                'trigger_payload': payload,
                'confidence': confidence,
                'method': method.upper()
            }
            
            # 根据漏洞类型和方法构建描述
            description = f"检测到{vuln_type}漏洞"
            
            if method == 'get':
                if vuln_type == 'DOM XSS':
                    description += f"，触发payload为：{payload}，目标URL：{trigger_url}"
                else:
                    if param:
                        description += f"(GET请求)，参数：{param}，触发payload：{payload}"
                    else:
                        description += f"(GET请求)，触发payload：{payload}"
                    description += f"，完整URL：{trigger_url}"
            elif method == 'post':
                description += f"(POST请求)，目标URL：{trigger_url}"
                if param:
                    description += f"，参数：{param}"
                description += f"，触发payload：{payload}"
                if form_data:
                    # 过滤掉敏感字段
                    filtered_form_data = {k: v for k, v in form_data.items() 
                                        if k.lower() not in ['user_token', 'csrf_token', 'token']}
                    if filtered_form_data:
                        form_info = ', '.join([f"{k}={v}" for k, v in filtered_form_data.items()])
                        description += f"，表单数据：{form_info}"
                        result_info['form_data'] = filtered_form_data
            
            if param:
                result_info['param'] = param
            
            result_info['description'] = description
            
            self.add_result(result_info)
        
        return self.get_results()

    def test_reflected_xss(self, url, param, payload, extra_params=None):
        """测试反射型XSS (GET)"""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        
        # 合并额外参数
        if isinstance(extra_params, dict):
            for k, v in extra_params.items():
                if k not in qs:
                    qs[k] = [v]
        
        # 获取原始响应作为基准
        original_resp = self.client.get(url)
        if not original_resp:
            return {'is_vuln': False}
        
        # 只测试真正的XSS payload
        if not self._is_xss_payload(payload):
            return {'is_vuln': False}
        
        variants = self._variant_payloads(payload)
        for variant in variants:
            new_qs = qs.copy()
            new_qs[param] = [variant]
            new_query = urlencode({k: v[0] for k, v in new_qs.items()})
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            if self.logger:
                self.logger.debug(f'Testing reflected XSS URL: {new_url}')
            
            resp = self.client.get(new_url)
            if not resp:
                continue
            
            # 检查payload是否被反射
            is_reflected, is_filtered, reflection_info = self.check_payload_reflection(original_resp, resp, variant)
            
            if is_reflected:
                return {
                    'is_vuln': True,
                    'vuln_type': 'Reflected XSS',
                    'payload': payload,
                    'trigger_url': new_url,
                    'param': param,
                    'confidence': 'high'
                }
            elif is_filtered:
                return {
                    'is_vuln': True,
                    'vuln_type': 'Reflected XSS (Filtered)',
                    'payload': payload,
                    'trigger_url': new_url,
                    'param': param,
                    'confidence': 'low'
                }
        
        return {'is_vuln': False}

    def test_post_reflected_xss(self, url, form_data, param, payload):
        """测试POST参数反射型XSS"""
        # 先获取原始响应作为基准
        original_resp = self.client.post(url, data=form_data)
        if not original_resp:
            return {'is_vuln': False}
        
        # 只测试真正的XSS payload
        if not self._is_xss_payload(payload):
            return {'is_vuln': False}
        
        variants = self._variant_payloads(payload)
        for variant in variants:
            new_form = form_data.copy()
            new_form[param] = variant
            
            if self.logger:
                form_info = ', '.join([f"{k}={v}" for k, v in new_form.items()])
                self.logger.debug(f'Testing POST reflected XSS URL: {url}, Data: {form_info}')
            
            resp = self.client.post(url, data=new_form)
            if not resp:
                continue
            
            # 检查payload是否被反射
            is_reflected, is_filtered, reflection_info = self.check_payload_reflection(original_resp, resp, variant)
            
            if is_reflected:
                return {
                    'is_vuln': True,
                    'vuln_type': 'Reflected XSS',
                    'payload': payload,
                    'trigger_url': url,
                    'param': param,
                    'form_data': new_form,
                    'confidence': 'high'
                }
            elif is_filtered:
                return {
                    'is_vuln': True,
                    'vuln_type': 'Reflected XSS (Filtered)',
                    'payload': payload,
                    'trigger_url': url,
                    'param': param,
                    'form_data': new_form,
                    'confidence': 'low'
                }
        
        return {'is_vuln': False}

    def test_stored_xss(self, url, form_data, payload):
        """测试存储型XSS（需要提交后检查）"""
        # 只测试真正的XSS payload
        if not self._is_xss_payload(payload):
            return {'is_vuln': False}
            
        variants = self._variant_payloads(payload)
        for variant in variants:
            # 创建包含payload的表单数据
            data = form_data.copy()
            
            # 寻找合适的字段注入payload
            injected = False
            for key in data:
                # 跳过按钮、提交、隐藏字段等
                if key.lower() in ['submit', 'button', 'csrf_token', 'user_token', 'token']:
                    continue
                data[key] = variant
                injected = True
                break
            
            if not injected:
                # 如果没有合适的字段，使用第一个字段
                if data:
                    first_key = list(data.keys())[0]
                    data[first_key] = variant
                    injected = True
            
            if not injected:
                continue
            
            if self.logger:
                form_info = ', '.join([f"{k}={v}" for k, v in data.items()])
                self.logger.debug(f'Testing stored XSS URL: {url}, Data: {form_info}')
            
            # 提交payload
            resp = self.client.post(url, data=data)
            if not resp:
                continue
            
            # 等待服务器处理
            time.sleep(1)
            
            # 获取页面查看payload是否被存储
            get_resp = self.client.get(url)
            if not get_resp:
                continue
            
            # 检查payload是否出现在响应中
            is_reflected, is_filtered, _ = self.check_payload_reflection(None, get_resp, variant, is_stored=True)
            
            if is_reflected:
                return {
                    'is_vuln': True,
                    'vuln_type': 'Stored XSS',
                    'payload': payload,
                    'trigger_url': url,
                    'form_data': data,
                    'confidence': 'medium'
                }
        
        return {'is_vuln': False}

    def test_dom_xss(self, url):
        """测试DOM型XSS（通过检查JS代码）"""
        resp = self.client.get(url)
        if not resp:
            return {'is_vuln': False}
        
        text = resp.text or ''
        
        # 检查常见的DOM XSS sink
        dom_sinks = [
            r'document\.write\s*\([^)]*',
            r'document\.writeln\s*\([^)]*',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'eval\s*\([^)]*',
            r'setTimeout\s*\([^)]*',
            r'setInterval\s*\([^)]*',
            r'Function\s*\([^)]*',
            r'location\.hash\s*[=:]',
            r'location\.search\s*[=:]',
            r'document\.location\s*[=:]',
            r'window\.location\s*[=:]',
            r'document\.URL\s*[=:]',
            r'document\.documentURI\s*[=:]',
            r'document\.baseURI\s*[=:]',
            r'document\.referrer\s*[=:]',
            r'window\.name\s*[=:]'
        ]
        
        # 检查是否包含用户输入来源
        input_sources = [
            r'location\.href',
            r'location\.search',
            r'location\.hash',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.baseURI',
            r'document\.referrer',
            r'window\.name',
            r'URLSearchParams',
            r'window\.location\.href'
        ]
        
        # 检查sink和source的组合
        found_sinks = []
        for sink_pattern in dom_sinks:
            matches = re.findall(sink_pattern, text, re.IGNORECASE)
            if matches:
                found_sinks.extend(matches)
        
        if found_sinks:
            # 检查是否有用户输入来源
            for source_pattern in input_sources:
                if re.search(source_pattern, text, re.IGNORECASE):
                    return {
                        'is_vuln': True,
                        'vuln_type': 'DOM XSS',
                        'payload': 'N/A (DOM检测)',
                        'trigger_url': url,
                        'confidence': 'low'
                    }
        
        return {'is_vuln': False}

    def check_payload_reflection(self, original_resp, test_resp, payload, is_stored=False):
        """
        检查payload是否被反射，并判断是否被过滤
        
        参数:
            original_resp: 原始响应（用于反射型XSS对比）
            test_resp: 测试响应
            payload: 测试的payload
            is_stored: 是否为存储型XSS检测
            
        返回:
            (is_reflected, is_filtered, reflection_info)
        """
        if not test_resp or not test_resp.text:
            return False, False, {}
        
        body = test_resp.text
        reflection_info = {
            'payload_in_response': False,
            'html_encoded': False,
            'url_decoded': False,
            'partial_encoded': False
        }
        
        # 对于非XSS payload（如'test'），直接返回False
        if not self._is_xss_payload(payload):
            return False, False, reflection_info
        
        # 1. 检查原始payload是否直接出现
        if payload in body:
            reflection_info['payload_in_response'] = True
            reflection_info['direct_reflection'] = True
            
            # 检查是否同时出现HTML编码版本
            html_escaped = payload.replace('<', '&lt;').replace('>', '&gt;')
            if html_escaped in body:
                reflection_info['html_encoded'] = True
                return True, True, reflection_info  # 被过滤但仍有反射
            
            # 检查payload是否被包含在HTML标签属性中（可能是正常使用）
            if self._is_payload_in_html_attribute(body, payload):
                reflection_info['in_html_attribute'] = True
                return False, False, reflection_info
            
            return True, False, reflection_info  # 直接反射，未过滤
        
        # 2. 检查HTML实体编码版本
        html_escaped = payload.replace('<', '&lt;').replace('>', '&gt;')
        if html_escaped in body:
            reflection_info['html_encoded'] = True
            return False, True, reflection_info  # 被HTML编码过滤
        
        # 3. 检查URL解码版本
        try:
            decoded = unquote(payload)
            if decoded in body and decoded != payload:
                reflection_info['url_decoded'] = True
                reflection_info['decoded_payload'] = decoded
                return True, False, reflection_info
        except:
            pass
        
        # 4. 检查部分编码版本
        # 检查尖括号是否被编码
        if '<' in payload and '&lt;' in body and '>' in payload and '&gt;' in body:
            # 尝试替换所有尖括号
            partially_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
            if partially_encoded in body:
                reflection_info['partial_encoded'] = True
                return False, True, reflection_info
        
        # 5. 对于存储型XSS，放宽检测条件
        if is_stored:
            # 检查payload的关键部分是否出现
            key_parts = []
            if '<script' in payload.lower():
                key_parts.append('script')
            if 'alert' in payload.lower():
                key_parts.append('alert')
            if 'onerror' in payload.lower():
                key_parts.append('onerror')
            if '<img' in payload.lower():
                key_parts.append('img')
            
            # 如果包含关键部分，检查是否以任何形式出现
            if key_parts:
                for part in key_parts:
                    if part.lower() in body.lower():
                        reflection_info['key_part_found'] = part
                        # 进一步检查是否是用户输入的一部分
                        # 这里可以添加更复杂的逻辑
                        return True, False, reflection_info
        
        # 6. 检查响应长度变化（仅适用于反射型XSS）
        if original_resp and not is_stored:
            orig_len = len(original_resp.text or '')
            test_len = len(body)
            length_diff = abs(test_len - orig_len)
            
            # 如果响应长度显著增加，可能包含我们的payload
            if length_diff > len(payload) * 0.5:  # 长度变化超过payload长度的一半
                # 进一步检查是否有我们的payload特征
                if self._contains_xss_indicators(body):
                    reflection_info['length_increased'] = True
                    reflection_info['length_diff'] = length_diff
                    return True, False, reflection_info
        
        return False, False, reflection_info

    def _is_xss_payload(self, payload):
        """检查是否为真正的XSS payload"""
        xss_indicators = [
            '<script',
            'onerror',
            'onload',
            'onclick',
            'onmouseover',
            'alert(',
            'prompt(',
            'confirm(',
            'eval(',
            'javascript:',
            '<img',
            '<svg',
            '<iframe',
            '<body',
            '<input'
        ]
        
        payload_lower = payload.lower()
        for indicator in xss_indicators:
            if indicator in payload_lower:
                return True
        
        # 检查是否包含HTML标签
        if re.search(r'<[a-zA-Z][^>]*>', payload):
            return True
        
        # 检查是否包含事件处理器
        if re.search(r'on[a-zA-Z]+\s*=', payload, re.IGNORECASE):
            return True
        
        return False

    def _is_payload_in_html_attribute(self, html, payload):
        """检查payload是否被包含在HTML标签属性中"""
        # 常见的HTML属性，payload出现在这些属性中可能是正常的
        safe_attributes = ['value', 'placeholder', 'title', 'alt', 'href', 'src']
        
        # 查找所有包含payload的标签
        pattern = rf'<[^>]*{re.escape(payload)}[^>]*>'
        matches = re.findall(pattern, html, re.IGNORECASE)
        
        for match in matches:
            # 提取属性
            attr_pattern = r'(\w+)\s*=\s*["\'][^"\']*["\']'
            attrs = re.findall(attr_pattern, match)
            
            for attr in attrs:
                if attr.lower() in safe_attributes:
                    return True
        
        return False

    def _contains_xss_indicators(self, text):
        """检查文本中是否包含XSS指标"""
        indicators = [
            '<script',
            'onerror=',
            'onload=',
            'onclick=',
            'onmouseover=',
            'alert(',
            'prompt(',
            'confirm(',
            'eval(',
            'javascript:'
        ]
        
        text_lower = text.lower()
        for indicator in indicators:
            if indicator in text_lower:
                return True
        return False

    def _variant_payloads(self, payload):
        """返回payload的多种变体"""
        variants = [payload]
        
        # 1. URL编码变体
        try:
            variants.append(quote(payload, safe=''))
            # 部分编码：只编码尖括号
            variants.append(payload.replace('<', '%3C').replace('>', '%3E'))
            # 双重编码
            variants.append(quote(quote(payload, safe=''), safe=''))
        except:
            pass
        
        # 2. HTML实体编码变体
        variants.append(payload.replace('<', '&lt;').replace('>', '&gt;'))
        # 十六进制实体编码
        variants.append(payload.replace('<', '&#x3c;').replace('>', '&#x3e;'))
        # 十进制实体编码
        variants.append(payload.replace('<', '&#60;').replace('>', '&#62;'))
        
        # 3. 大小写变体
        variants.append(payload.upper())
        variants.append(payload.lower())
        # 随机大小写
        random_case = ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        variants.append(random_case)
        
        # 4. 事件处理程序变体
        if 'on' in payload.lower():
            # 混合大小写的事件处理器
            if 'onerror' in payload.lower():
                variants.append(payload.replace('onerror', 'OnErRoR'))
            if 'onload' in payload.lower():
                variants.append(payload.replace('onload', 'OnLoAd'))
            if 'onclick' in payload.lower():
                variants.append(payload.replace('onclick', 'OnClIcK'))
        
        # 5. 简化的payload变体
        if '<script>' in payload.lower():
            variants.append('<script>alert(1)</script>')
        
        if '<img' in payload.lower():
            variants.append('<img src=x onerror=alert(1)>')
        
        # 去重并返回
        unique_variants = []
        seen = set()
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique_variants.append(v)
        
        return unique_variants[:20]  # 限制变体数量，避免过多请求