import yaml
import requests
import re
import base64
import sys
from urllib.parse import urlparse, parse_qs, unquote

INTERVAL = 0
URL = 'http://www.gstatic.com/generate_204' 

def get_servers():
    # 解析trojan url，生成字典，包含服务器内容
    url = sys.argv[1]

    content = requests.get(url).content

    content = base64.b64decode(content).decode()
    all_samples = content.split('\r\n')
    ret = []
    # Trojan URL
    for samp in all_samples:
        # 解析URL
        if samp:
            parsed_url = urlparse(samp)

            # 提取各部分信息
            protocol = parsed_url.scheme  # 协议类型
            password = parsed_url.username  # 用户ID
            server = parsed_url.hostname  # 服务器地址
            port = parsed_url.port  # 端口号
            params = parse_qs(parsed_url.query)  # 解析查询参数
            name = unquote(parsed_url.fragment)  # 解码服务器名称

            # 输出解析结果
            # print(f"协议类型: {protocol}")
            # print(f"用户ID: {userinfo}")
            # print(f"服务器地址: {host}")
            # print(f"端口号: {port}")
            # print(f"查询参数: {params}")
            # print(f"备注: {name}")
            result = {}
            result['name'] = name
            result['type'] = protocol
            result['server'] = server
            result['port'] = port
            result['password'] = password
            for key in params:
                if key=='allowInsecure':
                    val = params[key][0]
                    if val=='0':
                        result['udp']=True
                    else:
                        result['udp']=False
                if key=='sni':
                    val = params[key][0]
                    result['sni'] = val
            ret.append(result)
    return ret


servers = get_servers()

with open("my.yaml",'r',encoding='utf-8') as file:
    datamy = yaml.safe_load(file)

with open("adremoval.yaml",'r',encoding='utf-8') as file:
    adremoval = yaml.safe_load(file)

raw_rules = datamy['rules']

datamy['rules'] = adremoval['rules']+datamy['rules']

datamy['proxies'] = servers

countries = ['香港','日本','韩国','台湾','新加坡','美国','其他']
all_proxies=[]
countries = dict.fromkeys(countries)
for i in countries:
    countries[i]=[]

for proxy in datamy['proxies']:
    get = 0
    for country in countries:
        if country in proxy['name']:
            countries[country].append(proxy['name'])
            get = 1
            break
    if get==0:
        countries['其他'].append(proxy['name'])
    all_proxies.append(proxy['name'])

proxy_group = datamy['proxy-groups']

# 加入手动切换 和 自动选择 两个group
manual,auto = {},{}
manual['name'] = '手动切换'
manual['type'] = 'select'
manual['proxies'] = all_proxies
manual['interval'] = INTERVAL
manual['url'] = URL

auto['name'] = '自动选择'
auto['type'] = 'url-test'
auto['proxies'] = all_proxies
auto['interval'] = INTERVAL
auto['url'] = URL

proxy_group.append(manual)
proxy_group.append(auto)

# 加入各国节点列表

for country in countries:
    group = {}
    group['name'] = country
    group['type'] = 'url-test'
    group['proxies'] = countries[country]
    group['interval'] = INTERVAL
    group['url'] = URL
    proxy_group.append(group)

# 加入openai等特定分类
group = {}
group['name'] = 'openai'
group['type'] = 'select'
group['proxies'] = datamy['proxy-groups'][0]['proxies'][1:] # 去除香港
group['interval'] = INTERVAL
group['url'] = URL
proxy_group.append(group)

datamy['proxy-groups'] = proxy_group



with open('output.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(datamy, file, allow_unicode=True, sort_keys=False)



datamy['rules'] = raw_rules

with open('simple.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(datamy, file, allow_unicode=True, sort_keys=False)
