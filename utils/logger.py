import logging
import os
from config.settings import Config

class ScannerLogger:
    def __init__(self, config: Config):
        """
        初始化日志系统
        """
        self.logger = logging.getLogger("WebVulnScanner")
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        file_path = os.path.join(config.pwd, config.get("logging", "file_path"))
        if config.get("logging", "clear_old") and os.path.exists(file_path) and os.path.isfile(file_path):
            os.remove(file_path) 

        file_handler = logging.FileHandler(file_path, encoding='utf-8')
        file_handler.setLevel(config.get("logging", "file_level"))
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        if(config.get("logging", "console")):
            console_handler = logging.StreamHandler()
            console_handler.setLevel(config.get("logging", "console_level"))
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
            
        self.logger.info("日志系统初始化完成")


    def debug(self, msg):
        """调试日志"""
        self.logger.debug(msg)
        
    def info(self, msg):
        """信息日志"""
        self.logger.info(msg)

    def warning(self, msg):
        """警告日志"""
        self.logger.warning(msg)

    def error(self, msg):
        """错误日志"""
        self.logger.error(msg)
        
    def critical(self, msg):
        """严重错误日志"""
        self.logger.critical(msg)
        
    def log_vulnerability(self, vuln_info):
        """记录发现的漏洞"""
        self.logger.info(f"发现漏洞: {vuln_info}")