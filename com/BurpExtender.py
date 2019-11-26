#!/usr/bin/python
# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IMessageEditorTabFactory, IMessageEditorController
from burp import IHttpListener
from java.io import PrintWriter
from java.util import ArrayList
from threading import Lock
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JPanel
from javax.swing import JTable
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout
import time

import uuid


# 定义子类
def getHash(self):
    # 先md5

    pass


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController):
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
        # self._stdout.println("Hello Web Fuzz 2.0")
        install = time.strftime("%Y-%m-%d", time.localtime())
        self._stdout.println("+------------------------------+")
        self._stdout.println("|         Web Fuzz 2.0         |")
        self._stdout.println("|    Started @ " + install + "      |")
        self._stdout.println("+------------------------------+")
        # stderr.println("Hello erroutputs")
        self._log = ArrayList()  # java
        self._lock = Lock()
        # 定义burp插件的主界面
        # https: // blog.csdn.net / xietansheng / article / details / 74366517
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)  # 垂直分布
        # 定义上面组件为log
        self._dataModel = TableModel(self)
        logTable = LogJTable(self, self._dataModel)
        logscrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(logscrollPane)
        # 下面组件为request|response显示区域
        # tabs = JTabbedPane(JTabbedPane.TOP)
        requestResponseView = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        requestResponseView.setResizeWeight(0.5)
        requestPanel = JPanel()
        requestPanel.setLayout(BorderLayout())
        responsePanel = JPanel()
        responsePanel.setLayout(BorderLayout())

        requestResponseView.setLeftComponent(requestPanel)
        requestResponseView.setRightComponent(responsePanel)
        '''
         IMessageEditor createMessageEditor(IMessageEditorController contrpoller,
            boolean editable);
        '''
        # responseEditor = FuzzEditor(self)
        # requestEditor = FuzzEditor(self)
        self._requestView = callbacks.createMessageEditor(self, False)
        self._responseView = callbacks.createMessageEditor(self, False)
        # 界面由tabs选项卡改为两开界面(11.26)
        requestPanel.add(self._requestView.getComponent())
        responsePanel.add(self._responseView.getComponent())
        self._splitpane.setRightComponent(requestResponseView)

        # callbacks.registerProxyListener(self)
        # 美容UI
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(logscrollPane)
        callbacks.customizeUiComponent(requestResponseView)
        # 一定要加ITab,不然没有界面
        callbacks.addSuiteTab(self)
        # 注册httpListener
        callbacks.registerHttpListener(self)
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
        if toolFlag == 4 or toolFlag == 64 or toolFlag == 20:
            # 既有响应又有请求，很重要(不然会出现很大的bug)
            if not messageIsRequest:
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
                    # 给每个请求单独加一个fuzzid来做标识,目前未使用
                    uid = str(uuid.uuid4())
                    fuzzid = ''.join(uid.split('-'))
                    self._stdout.println("Url:" + str(url) + "\n" + "".join(newHeaders) + "\n" + bodyStrings)
                    try:
                        self._lock.acquire()
                        row = self._log.size()
                        # IHttpRequestResponsePersisted extends IHttpRequestResponse
                        self._log.add(LogEntry(toolFlag, messageInfo,
                                               self._helpers, self._callbacks))
                        # 通知表格发生变化
                        # self.fireTableRowsInserted(row,row)
                        self._dataModel.fireTableRowsInserted(row, row)
                        # 解决row 值不匹配
                        self._stdout.println(int(row + 1))
                        self._lock.release()
                    except Exception as e:
                        print("dataModel error", e)
                        return
                except Exception as e:
                    print("messageIsRequest is error!", e)
                    return
            else:
                pass

    # Give the new tab a name
    def getTabCaption(self):
        return self._labelName

    def getUiComponent(self):
        return self._splitpane

    '''
    public int getRowCount();
    public int getColumnCount();
    public Object getValueAt(int row, int column);
    '''


# https://docs.oracle.com/javase/7/docs/api/javax/swing/JTable.html
class TableModel(DefaultTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getColumnCount(self):
        return 10

    def getRowCount(self):
        # self._extender._stdout.println("test:"+str(self._extender._log.size()))
        return self._extender._log.size()

    # 设置表头
    def getColumnName(self, columnIndex):
        # {"#","Host","Methond","Url","Status",""}
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "Host"
        if columnIndex == 2:
            return "Tool"
        if columnIndex == 3:
            return "Method"
        if columnIndex == 4:
            return "Url"
        if columnIndex == 5:
            return "Status"
        if columnIndex == 6:
            return "Length"
        if columnIndex == 7:
            return "MIME"
        if columnIndex == 8:
            return "SSL"
        if columnIndex == 9:
            return "Time"
        return ""

    def getValueAt(self, row, columnIndex):
        logEntry = self._extender._log.get(row)
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return logEntry._host
        if columnIndex == 2:
            return self._extender._callbacks.getToolName(logEntry._toolFlag)
        if columnIndex == 3:
            return logEntry._method
        if columnIndex == 4:
            return logEntry._queryPath
        if columnIndex == 5:
            return logEntry._status
        if columnIndex == 6:
            return "Length"
        if columnIndex == 7:
            return logEntry._mime
        if columnIndex == 8:
            return "SSL"
        if columnIndex == 9:
            return "time"
        return ""


# Jtable https://www.169it.com/article/12959732718244742024.html
class LogJTable(JTable):
    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)

    # 解决界面上请求和响应被选中时实时更新
    def changeSelection(self, row, column, toggle, extend):
        try:
            # 获取选中的行的详细请求内容
            logEntity = self._extender._log.get(row)
            # void setMessage(byte[] message, boolean isRequest);

            self._extender._requestView.setMessage(logEntity._requestResponse.getRequest(), True)
            # 一直都是空，原因就是processHttpMessage去构造请求了
            # self._extender._stdout.println("test1:" + str(logEntity._requestResponse.getResponse()))
            try:

                self._extender._responseView.setMessage(logEntity._requestResponse.getResponse(), False)
                # 这里要判断下请求的响应是否存在，因为有请求不一定有响应
                '''
                 if(logEntity._requestResponse.getResponse()):
                    self._extender._responseView.setMessage(logEntity._requestResponse.getResponse(),False)
                else:
                    self._extender._responseView.setMessage(bytes[0], False)
                '''
            except Exception as e:
                print("_requestResponse error", e)
            # 设置下当前请求,很重要，因为tableMode模型的值就是从这里来获取
            self._extender.currentLogEntry = logEntity._requestResponse
        except Exception as e:
            print("jtable error", e)

        JTable.changeSelection(self, row, column, toggle, extend)


# 创建log实体类，来记录每个请求（实际就是将请求给抽象成模型）
# __init__魔术方法，只是将传入的参数来初始化该实例
# __new__用来创建类并返回这个类的实例
class LogEntry:
    def __init__(self, toolFlag, messageInfo, helpers, callbacks):
        self._callbacks = callbacks
        self._helpers = helpers
        self._toolFlag = toolFlag
        self._requestResponse = self._callbacks.saveBuffersToTempFiles(messageInfo)

        if self._requestResponse.getResponse():
            responseInfo = self._helpers.analyzeResponse(self._requestResponse.getResponse())
            self._status = responseInfo.getStatusCode()
            self._mime = responseInfo.getStatedMimeType()
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        self._method = requestInfo.getMethod()
        self._url = requestInfo.getUrl()
        # 取出path路径
        path = self._url.getPath()
        if self._url.getQuery():
            self._queryPath = str(path + "?" + self._url.getQuery())
        else:
            self._queryPath = str(path)
        self._host = self._url.getHost()


class FuzzEditor(IMessageEditorController):
    def __init__(self, extender):
        self._extender = extender

    def getHttpService(self):
        return self._extender.currentLogEntry.getHttpService()

    def getRequest(self):
        return self._extender.currentLogEntry.getRequest()

    def getResponse(self):
        return self._extender.currentLogEntry.getResponse()
