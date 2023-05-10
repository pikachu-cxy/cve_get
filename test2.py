import time
from collections import OrderedDict

import openpyxl
import requests
import yaml
from bs4 import BeautifulSoup
import datetime
import requests
import json
import csv
import sqlite3

from lxml import etree


def mail(text, msg):
    #关于邮箱账户配置，后面优化为配置文件
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.utils import formataddr
        my_sender = load_config()[1]  # 发件人邮箱账号
        my_pass = load_config()[2]  # 发件人邮箱授权码 / 腾讯企业邮箱请使用登陆密码
        recipients = load_config()[3]  # 收件人邮箱账号
        # 内容
        msg = MIMEText('{}\r\n{}'.format(text, msg), 'plain', 'utf-8')
        # [发件人邮箱昵称、发件人邮箱账号], 昵称随便
        msg['From'] = formataddr([text, my_sender])
        # [收件人邮箱昵称、收件人邮箱账号], 昵称随便
        msg['To'] = formataddr(["推送目标", recipients])

        # 邮件的主题、标题
        msg['Subject'] = "您好！您有新的漏了么外卖订单，请及时查看！"

        # 用的腾讯企业邮箱做的测试   如果要用其他邮箱的话
        # 用其他邮箱作为发件人的话,请将"smtp.exmail.qq.com" 修改为 "xxxxxxxxxx.xxxx.com"
        # 发件人邮箱中的SMTP服务器端口  我这里是腾讯企业邮箱465  请查看自己的SMTP服务器端口号
        server = smtplib.SMTP_SSL(load_config()[4], load_config()[5])
        server.login(my_sender, my_pass)
        server.sendmail(my_sender, recipients, msg.as_string())
        server.quit()  # 关闭连接
        print("邮件发送成功")
    except Exception as e:
        print("邮件发送失败: ", e)

def sendNews():

    print("初始化数据中！！！")

    '''
    {"cve_id": cve_id, "vul_vendor": vul_vendor, "cve_type": cve_type, "cvss_grade": cvss_grade, "cve_des": cve_des,
     "cve_ref": cve_ref})
     '''

    # 推送正文内容 返回漏洞情报和涉及的项目组两个列表
    vul_list = getNews()
    print(type(vul_list))
    print(vul_list)
    msg = ''

    #相关漏洞涉及项目组信息
    '''if len(group_list) > 0:
        for index in range(0, len(group_list)):
            msg = "\n\n涉及项目组如下： " + group_list[index] + msg'''
    #漏洞情报
    if vul_list != None:
        for index in range(0, len(vul_list)):
            msg = "\n\nCVE编号: " + vul_list[index]['cve_id'] + "\n厂商产品信息: " + vul_list[index]['vul_vendor'] + "\n漏洞类型: " + vul_list[index]['cve_type'] + "\n漏洞描述: " + vul_list[index]['cve_des'] + "\n漏洞参考链接: " + vul_list[index]['cve_ref'] + msg
    else:
        print('无漏洞！')
    # 推送标题
    text = r'GitHub CVE监控消息提醒！！！'
    print(msg)

    mail(text, msg)
    server(text, msg)

def pushList(raw_response,i=None):
    today_cve_info_tmp = {}
    cve_id = raw_response['CVE_data_meta']['ID']

    print(cve_id)
    # 漏洞影响厂商版本
    vul_vendor_first = raw_response['affects']['vendor']['vendor_data'][0]['vendor_name']
    #print(vul_vendor_first)
    vul_product = raw_response['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['product_name']
    print(type(vul_product))
    print(vul_product)
    vul_product_version = raw_response['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']
    print(vul_product_version)
    print(type(vul_product_version))

    vul_vendor = str(vul_vendor_first) + '-------' + str(vul_product) + ':' + str(vul_product_version)

    #如果漏洞信息包含资产组件，则继续
    group_tmp = has_contain_chars(xlsx_analysis_to_list(load_config()[6], load_config()[7]), vul_vendor)
    if len(group_tmp) > 0:
        print('contain 资产！')
    else:
        print('返回空')
        return 'not contain!'


    print(vul_vendor)

    # 漏洞类型
    cve_type = raw_response['problemtype']['problemtype_data'][0]['description'][0]['value']
    # cvss评分
    if i == None:
        print('cvss is xxx')
        cvss_grade = raw_response['impact']['cvss']['baseScore']
        print(cvss_grade)
    else:
        cvss_grade = raw_response['impact']['cvss'][i]['baseScore']
        print(cvss_grade)

    # 漏洞描述
    cve_des = raw_response['description']['description_data'][0]['value']
    # 参考数据链接  优化的点：参考链接只取录了一条
    cve_ref = raw_response['references']['reference_data'][0]['url']
    today_cve_info_tmp.update(
        {"cve_id": cve_id, "vul_vendor": vul_vendor, "cve_type": cve_type, "cvss_grade": cvss_grade, "cve_des": cve_des,
         "cve_ref": cve_ref})
    print(today_cve_info_tmp)
    return today_cve_info_tmp

def getNews():

    #漏洞危害值 建议取值7.0-9.0 后续写入配置文件
    vul_key = 7.0
    #临时列表
    today_cve_info = []
    group_info = []
    #得到昨日10点-今日10点的漏洞数据 配合每日10点计划任务运行
    today_date = datetime.date.today()
    yesterday = today_date + datetime.timedelta(-1)
    #proxies = {'http': 'http://127.0.0.1:8082'}
    api = "https://api.github.com/repos/CVEProject/cvelist/commits?since={}T10:00:00Z&until={}T10:00:00Z&per_page=100".format(
        yesterday, today_date)
    #api = "https://api.github.com/repos/CVEProject/cvelist/commits?since=20230505T00:00:00Z&until=20230505T23:59:59Z&per_page=100"
    # 加一个200判断，github访问连通性
    try:
        if requests.get(api).status_code == 200:
        #if requests.get(api, proxies=proxies).status_code == 200:
            json_str = requests.get(api, headers=github_headers,timeout=10).json()
            n = len(json_str)
            for i in range(0, n):
                cve_url = json_str[i]['url']
                commits_response = requests.get(cve_url).json()
                raw_json = commits_response['files']
                n1 = len(raw_json)
                for l in range(0, n1):
                    raw_url = raw_json[l]['raw_url']
                    print(raw_url)
                    raw_response = requests.get(raw_url).json()

                    # state
                    # 当状态为公开时 记录提醒 if
                    if raw_response['CVE_data_meta']['STATE'] == 'PUBLIC':

                        '''# cve id 年限？可能2021年确定了漏洞编号，2023才批露，年限暂不限制2023'''
                        cve_id = raw_response['CVE_data_meta']['ID']
                        # 评分 危害级别 如果没有impact 视作漏洞危害不大 则跳过？
                        if 'impact' in str(raw_response) and 'baseScore' in str(raw_response):
                            #print(type(raw_response['CVE_data_meta']['ID']))
                            if type(raw_response['impact']['cvss']) == list:
                                if len(raw_response['impact']['cvss']) > 1:
                                    print(len(raw_response['impact']['cvss']))
                                    for i in range(0, len(raw_response['impact']['cvss'])):
                                        print(raw_response['impact']['cvss'][i]['baseScore'])
                                        if float(raw_response['impact']['cvss'][i]['baseScore']) > vul_key:
                                            #通过cve官网检查是否确实存在该cve
                                            if check_true(cve_id):
                                                print('success')
                                                #if has_contain_chars(xlsx_analysis_to_list(''),)
                                                #这里判断pushlist返回的是否是字典，即today_cve_info_tmp ，如是的话加进today_cve_info
                                                dict_tmp = pushList(raw_response, i)
                                                print(type(dict_tmp))
                                                if type(dict_tmp) is dict:
                                                    today_cve_info.append(dict_tmp)
                                                    #print(raw_response['impact']['cvss'][i]['baseScore'])
                                                    break
                                elif float(raw_response['impact']['cvss'][0]['baseScore']) > vul_key:
                                    if check_true(cve_id):
                                        dict_tmp = pushList(raw_response, 0)
                                        print(type(dict_tmp))
                                        if type(dict_tmp) is dict:
                                            today_cve_info.append(dict_tmp)
                                            #print(raw_response['impact']['cvss'][0]['baseScore'])
                            # 一律加float转变为浮点类型
                            elif float(raw_response['impact']['cvss']['baseScore']) > vul_key:
                                if check_true(cve_id):
                                    dict_tmp = pushList(raw_response)
                                    print(type(dict_tmp))
                                    if type(dict_tmp) is dict:
                                        today_cve_info.append(dict_tmp)
                                        #print(raw_response['impact']['cvss']['baseScore'])

                        else:
                            pass
                            print('not in')
        #print(today_cve_info)
        #print(len(today_cve_info))
        #干掉可能重复的漏洞信息
        '''for i in range(len(today_cve_info)):
            for j in range(i + 1, len(today_cve_info)):
                if compare_dicts(today_cve_info[i], today_cve_info[j]):
                    print("dict{} and dict{} are similar".format(i + 1, j + 1))
                    today_cve_info.remove(today_cve_info[i])
                else:
                    print("dict{} and dict{} are different".format(i + 1, j + 1))'''
        unique_list = []
        for d in today_cve_info:
            if d not in unique_list:
                unique_list.append(d)
        print(group_info)
        return unique_list
    except Exception as e:
        print('github 无法联通！ 请检查网络是否有误或token是否过期 ！')
        #return [{"cve_id": 'cve_id', "vul_vendor": 'vul_vendor', "cve_type": 'cve_type', "cvss_grade": 'cvss_grade', "cve_des": 'cve_des',
     #"cve_ref": 'cve_ref'}]


def compare_dicts(dict1, dict2):
    """比较两个字典内容是否相似"""
    if len(dict1) != len(dict2):
        return False

    for key in dict1.keys():
        if key not in dict2:
            return False
        if dict1[key] != dict2[key]:
            return False

    return True

def check_true(cve_id):
    try:
        query_cve_url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve_id
        response = requests.get(query_cve_url, timeout=10)
        html = etree.HTML(response.text)
        des = html.xpath('//*[@id="GeneratedTable"]/table//tr[4]/td/text()')[0].strip()
        #print(des)
        if des == '**':
            return False
        return True
    except Exception as e:
        return False


def load_config():
    with open('config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
        github_token = config['base_config']['github_token']
        my_sender = config['base_config']['my_sender']
        my_pass = config['base_config']['my_pass']
        recipients = config['base_config']['recipients']
        smtp_server = config['base_config']['smtp_server']
        smtp_port = config['base_config']['smtp_port']
        filename = config['base_config']['xlsx_filename']
        sheet = config['base_config']['sheet_number']
        server1 = config['base_config']['server']
        return github_token, my_sender, my_pass, recipients, smtp_server, smtp_port, filename, sheet, server1

#解析xlsx,每行作为一个列表返回
def xlsx_analysis_to_list(file_name, sheet_number):

    # 打开Excel文件
    workbook = openpyxl.load_workbook(file_name)

    # 选择要读取的表格
    sheet = workbook[sheet_number]

    # 选择要读取的列（这里假设要读取第1列和第3列）
    # 优化为第一列作为索引标记（项目组名称）
    cols = [1, 2, 3, 4, 5, 6, 7]
    data_tmp = []
    # 遍历每一行，读取指定列的数据
    for row in sheet.iter_rows(min_row=2, values_only=True):
        data = [row[i - 1] for i in cols]  # 读取指定列的数据
        data_tmp.append(data)

    print('data_tmp: ', data_tmp)
    return data_tmp


#查找CVE内厂商应用是否包含项目组资产
def has_contain_chars(data_tmp, str2):

    lower2 = str2.lower()
    chars_tmp = []
    for i in range(0,len(data_tmp)):
        #从第一列开始，因为0列是项目组名称
        for j in range(1, len(data_tmp[i])):
            str_tmp = str(data_tmp[i][j])
            list_tmp = str_tmp.split('\n')
            print(list_tmp)
            for t in range(0, len(list_tmp)):
                if list_tmp[t].lower() in lower2:
                    print('包含！{}项目组资产： '.format(data_tmp[i][0]), list_tmp[t].lower())
                    chars_tmp.append('包含！{}项目组资产： '.format(data_tmp[i][0]) + list_tmp[t].lower())
    print(chars_tmp)
    return chars_tmp

# server酱  http://sc.ftqq.com/?c=code
def server(text, msg):
    try:
        uri = 'https://sc.ftqq.com/{}.send?text={}&desp={}'.format(load_config()[8], text, msg)  # 将 xxxx 换成自己的server SCKEY
        requests.get(uri, timeout=10)
    except Exception as e:
        pass

github_headers = {
    'Authorization': "token {}".format(load_config()[0])
}

# main函数
if __name__ == '__main__':

    # 优化
    # 1. 扫描一次就发送邮件。。 比较笨拙 只能每日固定时间内运行脚本 需要定时任务配合
    # 2. 如何更精准划分资产所属？ 如某某版本系统/组件属于此部门  或许需要数据库的时候来了！ 资产表
    # 3. 只读取了github上cve官方项目，可以拓展漏洞信息源
    # 4. 无数据库存储功能，不能方便的存储查询组件/系统历史相关漏洞  准备增加数据库（选型ing    漏洞表
    # 5. 未来适配GUI界面更方便   OR  适配web端？
    # 6. 如何增强程序的健壮性（如遇到网络不佳/网页格式更改等情况）
    '''7. 邮件漏洞重复了。。（要加个判断更新是否重复)  已解决✳ '''
    '''# 8. 增加其他提醒方式，如钉钉 飞书 企业微信 server酱等（可选） 已解决✳  加入了server酱进行微信提醒'''
    # 9. 搜索github其他仓库有无该CVE poc（应该以最近一周的cve高危漏洞搜索，最好需要数据库支持）
    ''' 10. 配合cve官网再次验证漏洞情报准确性  已解决✳ '''
    # 11. 加入翻译功能？ 将英文描述/漏洞类型 翻译为中文？


    print("cve  监控中 ...")


    sendNews()

    '''
    while True:
    获取当天时间，每日最后10分钟进行工作
        now = datetime.datetime.now()
        # 到达设定时间，结束内循环
        if now.hour == 23 and now.minute > 50:
            pass'''










