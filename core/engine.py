import json
from queue import Queue
import threading
from threading import Lock

from core.crawler import Crawler
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from utils.http_client import HttpClient
from utils.logger import ScannerLogger
from utils.login import LoginHelper
from config.settings import Config

from scanner.base import BaseScanner
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss import XSSScanner
from scanner.file_upload import FileUploadScanner

class ScannerEngine:
    def __init__(self, config: Config, logger: ScannerLogger):
        self.config = config
        self.logger = logger
        self.client = HttpClient(config, logger)  # 全局HTTP客户端（复用session）
        
        # 多线程相关初始化
        self.task_queue = Queue()  # 任务队列（存放待检测的URL/表单）
        self.results = []  # 最终漏洞结果集
        self.result_lock = Lock()  # 线程安全锁（防止多线程写结果冲突）
        self.scanners: list[BaseScanner]= []  # 初始化的漏洞扫描器列表
        
        # 加载启用的漏洞扫描模块
        self.setup_scanners()
        self.logger.info(f"扫描引擎初始化完成")

        # 如果配置了需要登陆，尝试登录
        if self.config.get("auth","enable"):
            login_helper = LoginHelper(self.client, self.config, self.logger)
            login_helper.login_dvwa()

    def setup_scanners(self):
        """初始化启用的漏洞扫描模块（读取config.ini的开关）"""
        if self.config.get("modules", "sql_injection"):
            sql_scanner = SQLInjectionScanner(self.client, self.logger, self.config)
            self.scanners.append(sql_scanner)
            self.logger.info("启用SQL注入扫描模块")
        
        if self.config.get("modules", "xss"):
            xss_scanner = XSSScanner(self.client, self.logger, self.config)
            self.scanners.append(xss_scanner)
            self.logger.info("启用XSS扫描模块")
        
        if self.config.get("modules", "file_upload"):
            upload_scanner = FileUploadScanner(self.client, self.logger, self.config)
            self.scanners.append(upload_scanner)
            self.logger.info("启用文件上传扫描模块")

    def run(self):
        start_url=self.config.get("scanner", "url")
        """引擎核心运行逻辑"""

        # 爬虫爬取所有待检测目标 (URL和表单)
        self.logger.info(f"开始爬取目标网站：{start_url}")
        crawler = Crawler(self.client, self.logger, self.config)
        urls, forms = crawler.crawl(start_url)  # 爬取URL和表单
        self.logger.info(f"爬虫完成：共计 {len(urls)} 个URL，{len(forms)} 个表单")

        # 构建检测任务队列 
        self.create_tasks(urls, forms)
        self.logger.info(f"任务队列构建完成：共 {self.task_queue.qsize()} 个检测任务")

        # 启动多线程执行任务 
        thread_count = self.config.get("scanner", "max_threads")  # 线程数
        self.logger.info(f"最多启动 {thread_count} 个扫描线程")
        threads: list[threading.Thread] = []
        for i in range(thread_count):
            t = threading.Thread(target=self.worker, name=f"Scanner-Thread-{i+1}")
            t.daemon = True  # 守护线程：主程序退出时线程自动结束
            t.start()
            threads.append(t)

        # 等待所有任务完成（队列清空）
        self.task_queue.join()
        # 等待所有线程退出
        for t in threads:
            t.join(timeout=1)

        self.logger.info("所有扫描任务执行完成")

        # 汇总所有扫描器的结果: 把每个扫描器返回的漏洞条目展开合并为扁平列表
        aggregated = []
        for scanner in self.scanners:
            try:
                r = scanner.get_results()
                if isinstance(r, list):
                    aggregated.extend(r)
            except Exception:
                continue
        self.results = aggregated
        self.logger.info(f"扫描结束：共发现 {len(self.results)} 个漏洞:{json.dumps(self.results, ensure_ascii=False, indent=2)}")

    def create_tasks(self, urls, forms):
        """构建任务队列：把URL/表单封装成任务，放进队列"""
        # URL任务
        for url in urls:
            self.logger.debug(f"添加URL任务: {json.dumps(url, ensure_ascii=False,indent=2)}")
            self.task_queue.put({
                "type": "url",
                "data": url
            })
        
        # 2. 表单任务
        for form in forms:
            self.logger.debug(f"添加表单任务: {json.dumps(form, ensure_ascii=False,indent=2)}")
            self.task_queue.put({
                "type": "form",
                "data": form
            })
        
            

    def worker(self):
        """多线程工作函数：每个线程循环从队列取任务执行"""
        thread_name = threading.current_thread().name
        self.logger.debug(f"线程 {thread_name} 启动，等待任务...")
        
        while True:
            try:
                # 取任务（block=True：队列空时阻塞；timeout=1：防止死等）
                task = self.task_queue.get(timeout=1)
                try:
                    # 执行单个任务的扫描
                    self.scan_target(task)
                except Exception as e:
                    self.logger.error(f"线程 {thread_name} 执行任务失败：{str(e)}")
                finally:
                    # 标记任务完成
                    self.task_queue.task_done()
            except Exception:
                # 队列超时无任务，线程退出
                self.logger.debug(f"线程 {thread_name} 无任务，退出")
                break

    def scan_target(self, task):
        """执行单个目标的扫描：调用所有启用的扫描器检测"""
        task_type = task["type"]
        task_data = task["data"]
        self.logger.debug(f"检测目标：{task_type} -> {json.dumps(task_data, ensure_ascii=False, indent=2)}")

        # 遍历所有启用的扫描器，逐个检测当前目标
        for scanner in self.scanners:
            # 每个扫描器的scan方法接收不同类型的目标（URL/表单）
            # scanner.scan should update its internal results via BaseScanner.add_result()
            try:
                scanner.scan(task_data)
            except Exception as e:
                self.logger.error(f"扫描器执行失败: {e}")

    # 结果添加
    def add_result(self, result):
        with self.result_lock:
            self.results.append(result)