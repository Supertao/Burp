#!/usr/bin/python
# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener,IMessageEditorTabFactory
from java.io import PrintWriter
from java.util import ArrayList
from threading import Lock
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JPanel
from javax.swing import JTable
import uuid


# 定义子类
def getHash(self):
    # 先md5

    pass


class BurpExtender(IBurpExtender, ITab, IHttpListener,IMessageEditorTabFactory):
    # Burp extensions 列表中的扩展名
    _extensionName = "Fuzz 2.0"
    _labelName = "Fuzz"

    # void
    def registerExtenderCallbacks(self, callbacks):
        # 表示私有变量
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # 实现你想实现的代码
        callbacks.setExtensionName(self._extensionName)
        # 控制台标准输出、错误输出
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        _stderr = PrintWriter(callbacks.getStderr(), True)
        self._stdout.println("Hello Web Fuzz 2.0")
        # stderr.println("Hello erroutputs")
        self._log=ArrayList()#java
        self._lock=Lock()
        # 定义burp插件的主界面
        # https: // blog.csdn.net / xietansheng / article / details / 74366517
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)  # 垂直分布
        #定义上面组件为log
        logTable=JTable()
        logscrollPane=JScrollPane(logTable)
        self._splitpane.setLeftComponent(logscrollPane)
        #下面组件为request|reponse
        tabs=JTabbedPane(JTabbedPane.TOP)
        test=JPanel()
        test1= JPanel()
        tabs.addTab("Request",test)
        tabs.addTab("Response",test1)
        self._splitpane.setRightComponent(tabs)

        # 注册httpListener
        callbacks.registerHttpListener(self)
        # callbacks.registerProxyListener(self)
        # 一定要加ITab,不然没有界面
        callbacks.addSuiteTab(self)

        return

    '''
    void processHttpMessage(int toolFlag,
            boolean messageIsRequest,
            IHttpRequestResponse messageInfo);
    拦截HTTP请求
    '''

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Proxy Spider Scanner Intruder
        # 判断请求是否是PROXY中的
        if toolFlag == 4:
            # 是请求则处理
            if not messageIsRequest:
                return
            if messageIsRequest == True:
                self._stdout.println("Enter print request")
                try:
                    # 使用requestinfo我们可以轻松的获得body和headers
                    requestInfo = self._helpers.analyzeRequest(messageInfo)
                    '''
                    IRequestInfo接口：
                    url 
                    method
                    headers
                    parameters(headers字段)
                    bodyoffset body位移
                    contentType(None 0,URL_ENCODED 1,CONTENT_TYPE_MULTIPART 2,CONTENT_TYPE_XML 3
                                CONTENT_TYPE_JSON 4,CONTENT_TYPE_AMF 5,CONTENT_TYPE_UNKNOWN -1)
                    
                    '''
                    # 请求地址（带参数并且没有解码的请求）
                    url = requestInfo.getUrl()  # java.net.URL
                    headers = requestInfo.getHeaders()
                    # headers是java list 需要转化成python list
                    newHeaders = list(headers)
                    bodyOffset = requestInfo.getBodyOffset()
                    # helpers中带bytes 转 string
                    bodyBytes = messageInfo.getRequest()[bodyOffset:]
                    bodyStrings = self._helpers.bytesToString(bodyBytes)
                    # 给每个请求单独加一个md5来做标识
                    uid = str(uuid.uuid4())
                    fuzzid = ''.join(uid.split('-'))
                    newHeaders.append("fuzzid: " + fuzzid)
                    # 重新构建http请求
                    newMessages = self._helpers.buildHttpMessage(newHeaders, bodyBytes)
                    messageInfo.setRequest(newMessages)
                    self._stdout.println("Url:" + str(url) + "\n" + "".join(newHeaders) + "\n" + bodyStrings)

                except Exception as e:
                    print("messageIsRequest is error!", e)
                    return

            return

    # Give the new tab a name
    def getTabCaption(self):
        return self._labelName

    def getUiComponent(self):
        return self._splitpane




# 创建log实体类，来记录每个请求（实际就是将请求给抽象成模型）
#__init__魔术方法，只是将传入的参数来初始化该实例
#__new__用来创建类并返回这个类的实例

