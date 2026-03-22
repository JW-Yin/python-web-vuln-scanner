import json
import os
pwd = os.path.dirname(os.path.abspath(__file__))

class PayloadLoader:
    """Payload加载器"""

    # 用 abspath 可以解决根目录存放项目时路径错误的问题
    def __init__(self, file_path=os.path.abspath(os.path.join(pwd, '../payloads.json'))):
        self.file_path = file_path
        self.payloads = {}
        self.load_payloads()

    def store_payloads(self):
        """保存payload到文件"""
        with open(self.file_path, 'w') as f:
            json.dump(self.payloads, f, indent=4)

    def load_payloads(self):
        """从文件加载payload"""
        with open(self.file_path, 'r') as f:
            self.payloads = json.load(f)

    def get_payloads(self, vuln_type, sub_type=None):
        """获取指定类型的payload"""
        if vuln_type not in self.payloads:
            return []
        if sub_type:
            return self.payloads[vuln_type].get(sub_type, [])
        return self.payloads[vuln_type]

    def add_payload(self, vuln_type, payload):
        """添加自定义payload"""
        if vuln_type not in self.payloads:
            self.payloads[vuln_type] = []
        self.payloads[vuln_type].append(payload)
        self.store_payloads()
        



