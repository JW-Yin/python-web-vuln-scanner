# Python Web Vulnerability Scanner
一款**轻量级、模块化、可扩展**的Python Web漏洞自动化扫描工具，聚焦检测SQL注入、XSS、文件上传三类高频Web漏洞，通过多线程并发提升扫描效率，支持整站自动化爬取、配置化参数控制与结构化报告输出。

## 技术栈
- **核心语言**：Python 3.9（标准库）
- **核心依赖**：`requests`（HTTP请求）、`BeautifulSoup4`（HTML解析）
- **核心能力**：`threading`（多线程并发）、`argparse`（命令行参数解析）、`configparser`（配置解析）
- **数据格式**：INI（配置）、JSON（Payload/报告）

## 项目结构
```
web-vuln-scanner/
├── scanner.py              # 主程序入口
├── requirements.txt        # 依赖包列表
├── README.md              # 项目说明文档
├── config.ini             # 全局配置文件
├── payloads.json          # 漏洞Payload库
├── config/                # 配置模块
│   ├── __init__.py
│   └── settings.py        # 配置管理
├── core/                  # 核心业务模块
│   ├── __init__.py
│   ├── engine.py         # 多线程扫描引擎
│   ├── crawler.py        # 页面爬虫与链接发现
│   └── reporter.py       # 扫描报告生成
├── scanner/              # 漏洞扫描器模块
│   ├── __init__.py
│   ├── base.py          # 扫描器基类
│   ├── sql_injection.py # SQL注入扫描器
│   ├── xss.py           # XSS漏洞扫描器
│   └── file_upload.py   # 文件上传扫描器
├── utils/                # 通用工具模块
│   ├── __init__.py
│   ├── http_client.py   # HTTP请求封装
│   ├── html_parser.py   # HTML解析增强
│   ├── url_tools.py     # URL处理工具
│   ├── payloads.py      # Payload库管理
│   └── logger.py        # 日志记录工具
├── tests/               # 单元测试目录
│   └── test_*.py
├── reports/             # 扫描报告输出目录
│   └── report.json
└── logs/                # 日志存储目录
    └── scanner.log
```

## 快速开始
### 1. 克隆仓库
```bash
git clone https://github.com/你的用户名/python-web-vuln-scanner.git
cd python-web-vuln-scanner
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 配置文件
编辑 `config.ini`，根据需求调整扫描参数：
```ini
[SCAN]
target_url = http://example.com  # 目标URL
thread_num = 10                   # 并发线程数
timeout = 10                      # 请求超时时间（秒）

[PATH]
payloads_path = ./payloads.json   # Payload库路径
reports_path = ./reports/          # 报告输出路径
logs_path = ./logs/                # 日志存储路径

[LOG]
level = INFO                       # 日志级别：DEBUG/INFO/ERROR
```

### 4. 运行扫描
```bash
# 基础扫描（使用配置文件参数）
python scanner.py

# 自定义参数扫描
python scanner.py -u http://test.com -t 20 -v sql,xss
```

## 使用说明
### 命令行参数
| 参数 | 全称       | 说明                     | 示例                     |
|------|------------|--------------------------|--------------------------|
| `-u` | `--url`    | 指定目标URL              | `-u http://example.com`  |
| `-t` | `--thread` | 指定并发线程数           | `-t 15`                  |
| `-v` | `--vuln`   | 指定扫描漏洞类型（逗号分隔） | `-v sql,xss,file_upload` |
| `-c` | `--config` | 指定配置文件路径         | `-c ./my_config.ini`     |

### 扫描报告
扫描完成后，结构化报告将输出至 `reports/report.json`，示例格式：
```json
{
  "scan_time": "2024-05-01 10:00:00",
  "target_url": "http://example.com",
  "total_urls": 50,
  "vuln_count": 3,
  "vulns": [
    {
      "type": "XSS",
      "url": "http://example.com/index.php?name=test",
      "payload": "<script>alert(1)</script>",
      "risk_level": "high",
      "description": "反射型XSS漏洞，Payload未被过滤"
    }
  ]
}
```

## 核心功能模块
### 1. 配置管理（`config/`）
- 统一管理全局配置，支持INI文件与命令行参数双重配置
- 提供标准化配置获取接口，降低模块耦合

### 2. 核心引擎（`core/`）
- **扫描引擎**：基于`threading`实现多线程并发调度，控制任务分配与异常处理
- **页面爬虫**：自动解析HTML提取链接，完成URL规范化与去重
- **报告生成**：汇总扫描结果，输出结构化JSON报告

### 3. 漏洞扫描器（`scanner/`）
- 采用“基类抽象+子类实现”模式，统一扫描器接口
- 支持SQL注入、XSS、文件上传三类漏洞检测，可快速扩展新类型

### 4. 通用工具（`utils/`）
- 封装HTTP请求、URL处理、HTML解析、日志记录等通用能力
- 提升代码复用率，降低业务模块复杂度

## 扩展方向
- 新增漏洞类型扫描器（如CSRF、命令执行、目录遍历）
- 支持HTML可视化报告、CSV批量分析报告
- 增加被动扫描模式（抓包分析流量）
- 集成漏洞修复建议库
- 增加代理池支持，避免IP被封
