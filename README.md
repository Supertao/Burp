# Burp

#bug
redis 未正常启动，会导致网页加载不了 
logtable 首次请求和响应面板为空

#2020.1.20 
1、修复makeHttp 响应为null的异常
2、处理json输入特殊字符，需转义
