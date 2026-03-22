import configparser
import json
import os

class Config:
    def __init__(self, pwd):
        self.pwd = pwd
        self.config = {}  # 用来存储所有配置的嵌套字典
        self.load()
        if(self.get("logging","console")):
            print(f"配置文件config初始化完成") # 后面解析命令行参数时会覆盖部分配置项

    def load(self):
        """加载配置文件，将所有配置存入 self.config 字典（已进行类型转换）"""
        parser = configparser.ConfigParser()
        # 读取配置文件（指定编码避免中文乱码）
        parser.read(os.path.join(self.pwd, "config.ini"), encoding='utf-8')

        # 遍历所有 section 和 key-value
        for section in parser.sections():
            self.config[section] = {}
            for key, value in parser.items(section):
                # 类型转换：自动识别整数、浮点数、布尔值
                if value.isdigit():
                    self.config[section][key] = int(value)
                elif value.replace('.', '', 1).isdigit(): # 仅替换一次
                    self.config[section][key] = float(value)
                elif value.lower() in ['true', 'false']:
                    self.config[section][key] = value.lower() == 'true'
                else:
                    self.config[section][key] = value

    def get(self, section, key, default=None):
        """获取配置项，支持默认值"""
        return self.config.get(section, {}).get(key, default)
    
    def set(self, section, key, value):
        """设置配置项"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value