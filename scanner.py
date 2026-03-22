import argparse
import json
import os

from utils.logger import *
from utils.http_client import *
from core.engine import ScannerEngine
from core.reporter import ReportGenerator
from config.settings import Config

def parse_args(config: Config, logger: ScannerLogger):
    """
    解析命令行参数
    返回: argparse.Namespace
    参数:
      -u, --url: 目标URL (必需)
      -m, --modules: 指定扫描模块 (可选，默认全部)
    """
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=False, help="必选，指明你要扫描的目标URL")
    parser.add_argument("-m", "--modules", nargs="*", default=None, help="可选，指明要使用的扫描模块，若未指明则使用全部模块")
    parser.add_argument("-l", "--level", help="可选，指明dvwa的难度级别，默认使用low")
    
    # 覆盖config中的相关设置
    if parser.parse_args().url is not None:
        config.set("scanner", "url", parser.parse_args().url)
    if parser.parse_args().modules is not None:
        mods = [m.lower() for m in parser.parse_args().modules]
        # support aliases: allow users to pass 'sql' or 'sql_injection'
        if not ("sql" in mods or "sql_injection" in mods):
            config.set("modules", "sql_injection", False)
        if not ("xss" in mods or "xss_reflected" in mods or "xss_stored" in mods):
            config.set("modules", "xss", False)
        if not ("upload" in mods or "file_upload" in mods):
            config.set("modules", "file_upload", False)
    if parser.parse_args().level is not None:
        config.set("dvwa", "security_level", parser.parse_args().level)

    logger.info("命令行参数解析完成")
    logger.debug(f"命令行参数解析完成：{json.dumps(parser.parse_args().__dict__, ensure_ascii=False, indent=2)}")
    logger.debug(f"当前config配置: {json.dumps(config.config, ensure_ascii=False, indent=2)}")
    return parser.parse_args()
    
def main(pwd=os.path.dirname(os.path.abspath(__file__))):
    """
    主函数
    流程:
      1. 加载config.ini配置
      2. 初始化日志系统
      3. 解析命令行参数
      4. 初始化扫描引擎
      5. 运行扫描
      6. 生成报告
    """

    # 加载配置文件
    config = Config(pwd)

    # 初始化日志系统
    logger = ScannerLogger(config)

    # 解析命令行参数
    parse_args(config, logger)
    
    # 初始化扫描引擎
    engine = ScannerEngine(config, logger)
    
    # 运行扫描
    engine.run()

    # 生成报告
    ReportGenerator(engine.results, config, logger).generate()

   
if __name__ == "__main__":
    main()