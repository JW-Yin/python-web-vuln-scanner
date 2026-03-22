import json
import os
import datetime

from config.settings import Config
from utils.logger import ScannerLogger

class ReportGenerator:
    def __init__(self, results, config:Config, logger:ScannerLogger):
        self.results = results
        self.config = config
        self.logger = logger
        self.logger.info("报告生成器初始化完成")

    def generate(self):
        """
        生成json报告
        返回: 报告文件路径列表
        """
        configured = self.config.get('reports', 'output_dir')
        base_path = os.path.abspath(os.path.join(self.config.pwd, configured))

        if configured.endswith(os.sep) or configured.endswith('/') or os.path.isdir(base_path):
            out_dir = base_path
            os.makedirs(out_dir, exist_ok=True)
            filename = f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            out_path = os.path.join(out_dir, filename)
        else:
            out_dir = os.path.dirname(base_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            out_path = base_path

        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'generated_at': datetime.datetime.now().isoformat(),
                    'summary': {
                        'total_vulnerabilities': len(self.results)
                    },
                    'vulnerabilities': self.results
                }, f, ensure_ascii=False, indent=2)
            self.logger.info(f"报告已生成: {out_path}")
            return [out_path]
        except Exception as e:
            self.logger.error(f"写入报告失败: {e}")
            return []
        