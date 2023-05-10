# cve_get
对github上cve官方的cvelist项目实时监控，将cvelist更新的漏洞信息与录入的资产信息做比对，如录入的资产组件与新出现的高危漏洞所涉及的系统/组件有关联，则通过邮件/微信告警

使用方法：  
1.在test.xlsx内填入好需要监控的资产组件信息  
2.修改congif.yaml文件，填入相应配置信息  
3.运行test2.py 即可愉快的接收漏洞情报啦  
```python3 test2.py```  
# todo
1.目前只读取了github上cve官方项目，可以拓展漏洞信息源  
2.加入图数据库neo4j，爬取历史cve数据，与现有资产组件相关联，方便查询指定组件对应的具体cve信息  
3.适配GUI界面更方便   OR  适配web端  
4.数据库完成后建表爬取cve的poc，从监控工具扩展为验证+监控工具

## Star Chart

[![Stargazers over time](https://starchart.cc/cxy5211314/cve_get.svg)](https://starchart.cc/cxy5211314/cve_get)
