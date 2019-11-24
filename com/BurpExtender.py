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
        self._stdout.println("Hello Web Fuzz 2.0")
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
        # 下面组件为request|reponse
        tabs = JTabbedPane(JTabbedPane.TOP)
        '''
         IMessageEditor createMessageEditor(IMessageEditorController controller,
            boolean editable);
        '''
        requestEditor = FuzzEditor()
        responeEditor = FuzzEditor()
        self._requestView = callbacks.createMessageEditor(requestEditor, False)
        self._responseView = callbacks.createMessageEditor(responeEditor, False)
        tabs.addTab("Request", self._requestView.getComponent())
        tabs.addTab("Response", self._responseView.getComponent())
        self._splitpane.setRightComponent(tabs)

        # callbacks.registerProxyListener(self)
        # 美容UI
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(logscrollPane)
        callbacks.customizeUiComponent(tabs)
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
        if toolFlag == 4:
            # 是请求则处理
            if not messageIsRequest:
                return

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
                try:
                    self._lock.acquire()
                    row = self._log.size()
                    self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo),
                                           self._helpers.analyzeRequest(messageInfo).getUrl()))
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

            return

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
    '''

    def getRowCount(self):
        try:
            return self._log.size
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "id"
        if columnIndex == 1:
            return "Tool"
        if columnIndex == 2:
            return "Url"
        return ""

    def getValueAt(self,row,column):
        logEntry=self._log.get(row)
        if column == 0:
            #self._stdout.println("id:" + str(logEntry._id))
            return 1
        if column == 1:
            return self._callbacks.getToolName(logEntry._toolFlag)
        if column == 2:
            return logEntry._url.toString()
    '''


# https://docs.oracle.com/javase/7/docs/api/javax/swing/JTable.html
class TableModel(DefaultTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getColumnCount(self):
        return 10

    def getRowCount(self):
        self._extender._stdout.println("test:" + str(self._extender._log.size()))
        return self._extender._log.size()

    def getValueAt(self, row, col):
        return int(row * col)

    # 设置表头
    def getColumnName(self, columnIndex):
        # {"#","Host","Methond","Url","Status",""}
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "Host"
        if columnIndex == 2:
            return "Methond"
        if columnIndex == 3:
            return "Url"
        if columnIndex == 4:
            return "Status"
        return ""


# Jtable https://www.169it.com/article/12959732718244742024.html
class LogJTable(JTable):
    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)

    # 解决界面上请求和响应被选中时实时更新
    def changeSelection(self, row, column, toggle, extend):


# 创建log实体类，来记录每个请求（实际就是将请求给抽象成模型）
# __init__魔术方法，只是将传入的参数来初始化该实例
# __new__用来创建类并返回这个类的实例
class LogEntry:
    def __init__(self, toolFlag, requestResponse, url):
        self._toolFlag = toolFlag
        self._requestResponse = requestResponse
        self._url = url


class FuzzEditor(IMessageEditorController):
    def getHttpService(self):
        return

    def getRequest(self):
        return

    def getResponse(self):
        return



