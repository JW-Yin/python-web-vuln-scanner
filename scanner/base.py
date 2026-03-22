from abc import ABC, abstractmethod
from utils import payloads

from utils.logger import *
from utils.http_client import *
from config.settings import Config

class BaseScanner(ABC):
    
    def __init__(self, http_client:HttpClient, logger:ScannerLogger, config:Config):
        """        
        参数:
            http_client: 用于发送HTTP请求的客户端
            logger: 日志记录器（可选）
            config: 配置字典（可选）
        """
        self.client = http_client
        self.logger = logger
        self.config = config
        self.results = []
        self.payloads = payloads.PayloadLoader()

    
    @abstractmethod
    def scan(self, target):
        """
        扫描目标
        
        参数:
            target: 目标URL（字符串）或目标信息（字典）
        
        返回:
            list: 发现的漏洞列表
        """
        pass
    
    def add_result(self, vulnerability):
        """
        添加漏洞结果
    
        参数:
            vulnerability: 漏洞信息字典
            必须包含: type, url, confidence
        """
        self.results.append(vulnerability)

        # 获取方法信息，默认为GET
        method = vulnerability.get('method', 'GET')
    
        # 获取触发payload
        trigger_payload = vulnerability.get('trigger_payload', '')
    
        # 构建日志信息
        log_msg = f"发现 {vulnerability['type']} 漏洞 ({method}请求) "
        log_msg += f"URL: {vulnerability['url']} "
    
        if trigger_payload:
            log_msg += f"触发payload: {trigger_payload} "
    
        log_msg += f"(置信度: {vulnerability['confidence']})"
    
        self.logger.info(log_msg)
    
    def get_results(self):
        """获取所有结果"""
        return self.results
    
    @property
    def has_vulnerabilities(self):
        """检查是否有漏洞"""
        return len(self.results) > 0
    
    def clear_results(self):
        """清空结果"""
        self.results = []