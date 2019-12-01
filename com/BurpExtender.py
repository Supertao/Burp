#!/usr/bin/python
# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IMessageEditorTabFactory, IMessageEditorController, IContextMenuFactory
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
from java.awt import FlowLayout
from javax.swing import JCheckBox
from javax.swing import JButton
from javax.swing import JOptionPane
from java.awt.event import ActionListener
from java.awt.event import MouseAdapter
from javax.swing import BorderFactory
from java.lang import Boolean
from javax.swing import ScrollPaneConstants
from javax.swing import JPopupMenu
from javax.swing import JMenuItem
import time
import uuid
import redis
from hashlib import md5


# clear redis action
class actionRunMessage(ActionListener):
    def actionPerformed(self, e):
        r = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=True)
        listkey = r.keys('*bloomfilter*')
        for key in listkey:
            r.delete(key)
        #       #几种弹窗的形式：https://www.cnblogs.com/guohaoyu110/p/6440333.html
        JOptionPane.showMessageDialog(None, "Clear Redis Successfully!")


# 删除选中的行,最终要删除列表中的实体
class deleteLogtable(ActionListener):
    def __init__(self, extender, row):
        self._extender = extender
        self._row = row

    def actionPerformed(self, evt):
        # 通过获取按钮的内容来做相对的响应（https://www.cnblogs.com/dengyungao/p/7525013.html）
        buttonName = evt.getActionCommand()
        self._extender._stdout.println(buttonName)
        if buttonName == "Remove Selected":
            if self._row == -1:
                return
            for i in self._row:
                self._extender._stdout.println("remove:" + str(i))
                self._extender._log.remove(i)
                # 一定要通知数据模型更新数据
                self._extender._dataModel.fireTableDataChanged()
            # JOptionPane.showMessageDialog(None, "Remove Successfully!")
        # 一定要有二次点击确定,防止误删除
        if buttonName == "Clear All Histroy":
            self._extender._stdout.println(buttonName)
            if self._row == -1:
                return
            isSure = JOptionPane.showMessageDialog(self._extender.logTable, "Are you Sure to Clear All Histroy?",
                                                   "Sure",
                                                   JOptionPane.YES_NO_CANCEL_OPTION)
            self._extender._stdout.println("xxx:" + str(isSure))
            # JOptionPane.YES_OPTION 0
            # 此处有bug,目前无法获取到isSure的正确值
            if isSure == None:
                self._extender._log.clear()
                self._extender._stdout.println("clear all history" + str(self._extender._log.size()))
                # 一定要通知数据模型更新数据
                self._extender._dataModel.fireTableDataChanged()


class popmenuListener(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, evt):
        # 右键值为3
        if evt.getButton() == 3:
            # 创建弹窗对象
            mpopMenu = JPopupMenu()
            deleteMenu = JMenuItem("Remove Selected")
            repeaterMenu = JMenuItem("Send to Repeater")
            copyMenu = JMenuItem("Copy URL")
            clearMenu = JMenuItem("Clear All Histroy")

            mpopMenu.add(deleteMenu)
            mpopMenu.add(repeaterMenu)
            # 添加一条分割符，达到提示的效果
            mpopMenu.addSeparator()
            mpopMenu.add(clearMenu)
            mpopMenu.addSeparator()
            mpopMenu.add(copyMenu)
            # 通过点击位置找到点击为表格中的行
            self._extender._focusedRow = self._extender.logTable.getSelectedRows();
            self._extender._stdout.println(self._extender._focusedRow)
            # 一定要为按钮添加点击事件
            deleteMenu.addActionListener(deleteLogtable(self._extender, self._extender._focusedRow))
            clearMenu.addActionListener(deleteLogtable(self._extender, self._extender._focusedRow))
            # deleteMenu.addActionListener()
            # 一定要指定位置显示弹窗
            mpopMenu.show(self._extender.logTable, evt.getX(), evt.getY())


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory):
    # Burp extensions 列表中的扩展名
    _extensionName = "Fuzz 2.0"
    _labelName = "Web Fuzz"

    # void
    def registerExtenderCallbacks(self, callbacks):
        # 表示私有变量
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # 用来识别选中的是哪列
        self._focusedRow = 0
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

        # 0.定义burp插件的主界面（上中下三个部分）
        # https: // blog.csdn.net / xietansheng / article / details / 74366517
        self._mainPanel = JPanel()
        self._mainPanel.setLayout(BorderLayout())
        # createEmptyBorder(int top,int left,int bottom,int right)
        # self._mainPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5))
        # 1.定义Filter组件
        filterPane = JPanel()
        filterPane.setLayout(FlowLayout(FlowLayout.LEFT))
        # 中文乱码
        filterPane.setBorder(BorderFactory.createTitledBorder("Configure"))
        topPane = JPanel()
        topPane.setLayout(FlowLayout(FlowLayout.LEFT))

        # 颜色对照表https://docs.oracle.com/javase/7/docs/api/java/awt/Color.html
        # filterPane.setBorder(BorderFactory.createEmptyBorder(2,5, 2, 5))
        # filterPane.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY,1))
        selectProxy = JCheckBox("Proxy")
        selectRepeater = JCheckBox("Repeater")
        selectIntruder = JCheckBox("Intruder")
        selectCookies = JCheckBox("Cookies")
        redisClear = JButton("Redis Clear")
        redisClear.addActionListener(actionRunMessage())
        connDb = JButton("ConnDb")
        topPane.add(connDb)
        topPane.add(redisClear)
        filterPane.add(topPane)
        filterPane.add(selectProxy)
        filterPane.add(selectRepeater)
        filterPane.add(selectIntruder)
        filterPane.add(selectCookies)
        self._mainPanel.add(filterPane, BorderLayout.PAGE_START)  # 上部分

        # 2.定义log记录组件
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)  # 垂直分布
        self._dataModel = TableModel(self)
        self.logTable = LogJTable(self, self._dataModel)
        # 绑定点击事件
        self.logTable.addMouseListener(popmenuListener(self))

        # 设置列宽
        for i in range(self.logTable.getColumnCount()):
            # python
            tablecolumn = self.logTable.getColumnModel().getColumn(i)
            tablecolumn.setPreferredWidth(self._dataModel.getCloumnWidth(i))
        # 设置下水平滚动，垂直滚动ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED,ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        logscrollPane = JScrollPane(self.logTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                                    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        splitpane.setLeftComponent(logscrollPane)

        # 3.下面组件为request|response显示区域
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
        splitpane.setRightComponent(requestResponseView)
        self._mainPanel.add(splitpane, BorderLayout.CENTER)

        # callbacks.registerProxyListener(self)
        # 美容UI
        callbacks.customizeUiComponent(splitpane)
        callbacks.customizeUiComponent(self.logTable)
        callbacks.customizeUiComponent(logscrollPane)
        callbacks.customizeUiComponent(requestResponseView)
        # 一定要加ITab,不然没有界面
        callbacks.addSuiteTab(self)
        # 注册httpListener
        callbacks.registerHttpListener(self)
        return

    # 定义子菜单
    def createMenuItems(self, invocation):
        pass

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
                    # capacity是容量,error_rate是能容忍的误报率,超过误报率，抛出异常
                    # f=BloomFilter(capacity=1000, error_rate=0.001)
                    # self._stdout.println(bitarray(10))
                    # 给每个请求单独加一个fuzzid来做标识,目前未使用
                    uid = str(uuid.uuid4())
                    fuzzid = ''.join(uid.split('-'))
                    self._stdout.println("Url:" + str(url) + "\n" + "".join(newHeaders) + "\n" + bodyStrings)
                    try:
                        self._lock.acquire()
                        row = self._log.size()
                        bloom = BloomFilter()
                        # 解决URL去重，1 布隆过滤器 2 哈希表去重
                        # https://www.cnblogs.com/i-love-python/p/11537720.html
                        isExists = bloom.isContains(str(url))
                        self._stdout.println(isExists)
                        # IHttpRequestResponsePersisted extends IHttpRequestResponse
                        if not isExists:
                            self._log.add(LogEntry(toolFlag, messageInfo,
                                                   self._helpers, self._callbacks))
                            bloom.insert(str(url))
                            # 通知表格发生增加的变化
                            # self.fireTableRowsInserted(row,row)
                            self._dataModel.fireTableRowsInserted(row, row)
                            # 解决row 值不匹配
                            # self._stdout.println(int(row + 1))
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
        return self._mainPanel

    '''
    public int getRowCount();
    public int getColumnCount();
    public Object getValueAt(int row, int column);
    '''


# https://docs.oracle.com/javase/7/docs/api/javax/swing/JTable.html
class TableModel(DefaultTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getCloumnWidth(self, columnIndex):
        if columnIndex == 1:
            return 120
        if columnIndex == 4:
            return 380
        return 40

    def getColumnCount(self):
        return 11

    def getRowCount(self):
        # self._extender._stdout.println("test:"+str(self._extender._log.size()))
        return self._extender._log.size()

    def getColumnClass(self, columnIndex):
        if columnIndex == 8:
            return Boolean
        return str

    def isCellEditable(self, row, columnIndex):
        return False

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
        if columnIndex == 10:
            return "Comment"
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
            if logEntry._protocol == "https":
                return True
            else:
                return False
        if columnIndex == 9:
            return logEntry._time
        if columnIndex == 10:
            return "Comment"
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
        self._time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self._protocol = self._requestResponse.getHttpService().getProtocol()


class FuzzEditor(IMessageEditorController):
    def __init__(self, extender):
        self._extender = extender

    def getHttpService(self):
        return self._extender.currentLogEntry.getHttpService()

    def getRequest(self):
        return self._extender.currentLogEntry.getRequest()

    def getResponse(self):
        return self._extender.currentLogEntry.getResponse()


class simpleHash():
    def __init__(self, cap, seed):
        self.cap = cap
        self.seed = seed

    def hash(self, value):
        ret = 0
        for i in range(len(value)):
            ret += self.seed * ret + ord(value[i])
        return (self.cap - 1) & ret


class BloomFilter():
    def __init__(self, host='127.0.0.1', port=6379, db=0, blockNum=1, key='bloomfilter'):
        """
        :param host: the host of Redis
        :param port: the port of Redis
        :param db: witch db in Redis
        :param blockNum: one blockNum for about 90,000,000; if you have more strings for filtering, increase it.
        :param key: the key's name in Redis
        """
        self.server = redis.Redis(host=host, port=port, db=db)
        self.bit_size = 1 << 31  # Redis的String类型最大容量为512M，现使用256M
        self.seeds = [5, 7, 11, 13, 31, 37, 61]
        self.key = key
        self.blockNum = blockNum
        self.hashfunc = []
        for seed in self.seeds:
            self.hashfunc.append(simpleHash(self.bit_size, seed))

    def isContains(self, str_input):
        if not str_input:
            return False
        m5 = md5()
        m5.update(str_input)
        str_input = m5.hexdigest()
        ret = True
        name = self.key + str(int(str_input[0:2], 16) % self.blockNum)
        for f in self.hashfunc:
            loc = f.hash(str_input)
            ret = ret & self.server.getbit(name, loc)
        return ret

    def insert(self, str_input):
        m5 = md5()
        m5.update(str_input)
        str_input = m5.hexdigest()
        name = self.key + str(int(str_input[0:2], 16) % self.blockNum)
        for f in self.hashfunc:
            loc = f.hash(str_input)
            self.server.setbit(name, loc, 1)
