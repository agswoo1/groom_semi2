import configparser
import os

def load_config(config_file='config.ini'):
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"[!] 설정 파일이 존재하지 않습니다: {config_file}")

    config = configparser.ConfigParser()
    config.read(config_file)

    required_sections = {
        'SERVER': ['ServerIP'],
        'API': ['ApiKey'],
        'FILE': ['FilePath'],
        'AVM': ['AVM_Name'],
        'Frida': ['Frida_Script'],
        'Encryption_method': ['encryption_method'],
    }

    for section, keys in required_sections.items():
        if section not in config:
            raise KeyError(f"[!] 설정 파일에 '{section}' 섹션이 없습니다.")
        for key in keys:
            if key not in config[section] or not config[section][key].strip():
                raise KeyError(f"[!] 설정 파일의 '{section}' 섹션에 '{key}' 항목이 없거나 비어 있습니다.")

    return {
        'server_ip': config['SERVER']['ServerIP'],
        'api_key': config['API']['ApiKey'],
        'apk_path': config['FILE']['FilePath'],
        'avm_name': config['AVM']['AVM_Name'],
        'frida_script': config['Frida']['Frida_Script'],
        'encryption_method': config['Encryption_method']['encryption_method'],
    }
