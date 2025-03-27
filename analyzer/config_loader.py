# analyzer/config_loader.py

import configparser
import os

def load_config(config_file='config.ini', encoding='utf-8'):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"[!] 설정 파일이 존재하지 않습니다: {config_file}")

    config = configparser.ConfigParser()
    with open(config_file, 'r', encoding=encoding) as f:
        config.read_file(f)
    required_sections = {
        'signing': ['sign_tool', 'apksigner_path', 'keystore', 'alias', 'storepass', 'keypass'],
        'mobsf': ['api_key', 'host', 'MobSF'],
        'FILE': ['FilePath'],
        'Frida': ['Frida_Script'],
        'dynamic': ['package_name', 'app_name', 'js_report_output', 'wait_time'],
        'pdf': ['wkhtmltopdf_path']
    }
    

    for section, keys in required_sections.items():
        if section not in config:
            raise KeyError(f"[!] 설정 파일에 '{section}' 섹션이 없습니다.")
        for key in keys:
            if key not in config[section] or not config[section][key].strip():
                raise KeyError(f"[!] 설정 파일의 '{section}' 섹션에 '{key}' 항목이 없거나 비어 있습니다.")

    return {
        'signing': dict(config['signing']),
        'mobsf': dict(config['mobsf']),
        'FILE': {
            'apk_path': config['FILE']['FilePath']
        },
        'Frida': {
            'script': config['Frida']['Frida_Script']
        },
        'dynamic': {
            'package_name': config['dynamic']['package_name'],
            'app_name': config['dynamic']['app_name'],
            'js_report_output': config['dynamic']['js_report_output'],
            'wait_time': int(config['dynamic']['wait_time']),
        },
        'pdf': {
            'wkhtmltopdf_path': config['pdf']['wkhtmltopdf_path']
        }
    }
