技术栈：
    python3.9标准库 + threading + requests + BeautifulSoup + argparse

项目结构说明：
    web-vuln-scanner/
    ├── scanner.py              # 主程序入口
    ├── requirements.txt        # 依赖包列表
    ├── README.md              # 项目说明文档
    ├── config.ini             # 配置文件
    ├── config/                # 配置模块
    │   ├── __init__.py
    │   └── settings.py        # 配置管理
    ├── core/                  # 核心模块
    │   ├── __init__.py
    │   ├── engine.py         # 扫描引擎（多线程控制）
    │   ├── crawler.py        # 页面爬取与链接发现
    │   └── reporter.py       # 报告生成
    ├── scanner/              # 扫描器模块
    │   ├── __init__.py
    │   ├── base.py          # 扫描器基类
    │   ├── sql_injection.py
    │   ├── xss.py
    │   └── file_upload.py
    ├── utils/                # 工具函数
    │   ├── __init__.py
    │   ├── http_client.py   # HTTP请求封装
    │   ├── html_parser.py   # HTML解析增强
    │   ├── url_tools.py     # URL处理工具
    │   ├── payloads.py      # 漏洞Payload库
    │   └── logger.py        # 日志记录
    ├── tests/               # 测试文件
    │   └── test_*.py
    ├── reports/             # 输出报告目录
    │   └── (生成的文件)
    └── logs/                # 日志目录
        └── scanner.log

实现优先级建议
第一阶段：基础框架 (1-2天)
config/settings.py - 配置管理

utils/logger.py - 日志系统

utils/http_client.py - HTTP客户端

scanner.py - 主程序框架

第二阶段：核心工具 (1-2天)
utils/url_tools.py - URL处理

utils/html_parser.py - HTML解析

utils/payloads.py - Payload库

第三阶段：扫描器实现 (2-3天)
scanner/base.py - 扫描器基类

scanner/sql_injection.py - SQL注入扫描器

scanner/xss.py - XSS扫描器

scanner/file_upload.py - 文件上传扫描器

第四阶段：引擎与爬虫 (1-2天)
core/crawler.py - 页面爬虫

core/engine.py - 扫描引擎

第五阶段：报告与优化 (1-2天)
core/reporter.py - 报告生成器

性能优化与测试