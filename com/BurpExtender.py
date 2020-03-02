#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64
import json
import os
import re
import string
import threading
import time
import uuid
from collections import OrderedDict
from hashlib import md5
from threading import RLock

import redis
import yaml
from burp import IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory
from burp import IHttpListener, IScannerCheck, IIntruderPayloadGenerator, IIntruderPayloadGeneratorFactory
from jarray import array
from java.awt import BorderLayout
from java.awt import Color
from java.awt import Dimension
from java.awt import FlowLayout
from java.awt.event import ActionListener
from java.awt.event import FocusListener
from java.awt.event import MouseAdapter
from java.io import FileOutputStream
from java.io import PrintWriter
from java.lang import Boolean
from java.util import ArrayList
from javax.swing import BorderFactory
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JFileChooser
from javax.swing import JLabel
from javax.swing import JMenu, JMenuItem
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JPopupMenu
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JTextField
from javax.swing import ListCellRenderer
from javax.swing import ScrollPaneConstants
from javax.swing.table import DefaultTableModel
from javax.swing.table import TableCellRenderer, DefaultTableCellRenderer


class Payload():
    def __init__(self, filename):
        self.filename = filename

    def generator(self):
        PAYLOADS = []
        with open(self.filename, 'r') as payload:
            line = payload.readline()
            while line != '':
                PAYLOADS.append(line.strip('\n'))
                line = payload.readline()
        return PAYLOADS

    # 将用户添加的保存到文件中去
    def saveToFile(self):
        pass

    # 读取yaml文件
    def readYaml(self, yamlfile):
        with open(yamlfile, 'r') as f:
            yaml_dict = yaml.load(f.read())
        return yaml_dict

    def readYaml2(self,yamlfile):
        with open(yamlfile, 'r', encoding='utf-8') as f:
            file_content = f.read()
        content = yaml.load(file_content, yaml.FullLoader)
        return content


# 定义一个基本的Fuzzer类
class BaseFuzzer:
    def name(self):
        raise NotImplementedError

    def check(self, data):
        raise NotImplementedError

    def getMutations(self):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError


class BasicTypeFuzzer:
    def __init__(self):
        self.mutations = []

    def reset(self):
        self.mutations = []

    def name(self):
        return "BaseType"

    def findType(self, data):
        if data is None:
            return 'string'
        try:
            val = int(data)
            return 'integer'
        except ValueError:
            pass
        try:
            val = float(data)
            return 'float'
        except ValueError:
            pass
        printable = sum([int(x in string.printable) for x in data]) == len(data)
        if printable:
            forbidden = ('<', '>', ':', '"', '|', '?', '*')
            for f in forbidden:
                if f in data:
                    return 'string'
            if data.count('/') <= 1 and data.count('\\') <= 1:
                return 'string'
            try:
                if (len(data) % 4 != 0 or data.endswith('=')) and \
                        base64.b64encode(base64.b64decode(data)) == data:
                    return 'string'
            except:
                pass
            regexes = (
                # windows path
                r'^(?:[a-zA-Z]:)?\\?[\\\S|*\S]?.*$',
                # linux path
                r'^(\/?[^\/]*)+'
            )
            for r in regexes:
                if re.match(r, data, re.I):
                    return 'path'
            return 'string'
        else:
            return ''

    # 变异算法
    def getMutations(self, data):
        mutations = []
        ordered = OrderedDict()
        varType = self.findType(data)
        # 如果识别出string，
        if varType == 'string':
            mutations = self.stringMutations(mutations)
        elif varType == 'integer':
            payload = 'Integer Fuzz'
            mutations.append(payload)

        for mut in mutations:
            ordered[mut] = True
        '''
        dic = collections.OrderedDict()
        dic['k1'] = 'v1'
        dic['k2'] = 'v2'
        print(dic.keys())

        # 输出：odict_keys(['k1', 'k2'])
        '''
        return ordered.keys()

    def stringMutations(self, mutations):
        p = Payload("Fuzzing.pay")
        for i in p.generator():
            i = json.dumps(i)
            # print(i)
            mutations.append(i)

        return mutations


'''
1、对json建模，获取json每个key的type类型(string、int、bool、float、path(跨目录)、url（SSRF）)
2、拆分json的key-vaule,对应第一步中的type类型，然后替换相对的payload
3、根据界面相似度、响应状态码、错误提示等来识别
'''


class JsonFuzzer(BaseFuzzer):
    def name(self):
        return "JSONFuzzer"

    def check(self, data):
        try:
            json.load(data)
            return True
        except Exception as e:
            return False
            print("JSON error!", e)

    @staticmethod
    def _construct_key(previous_key, separtor, new_key):
        if previous_key:
            return "{}{}{}".format(previous_key, separtor, new_key)
        else:
            return new_key

    '''
    字典的每个键值
    key = > value
    对用冒号: 分割，每个键值对之间用逗号, 分割，整个字典包括在花括号
    {}
    '''

    @staticmethod
    def json_key(dict_json):
        _orderedDict = OrderedDict()

        def _json_key(object_, key):
            # 判断是否字典类型isinstance 返回True False
            if isinstance(object_, dict):
                for object_key in object_:
                    # 如果dict_json依旧是字典类型
                    if isinstance(object_[object_key], dict):
                        _json_key(object_[object_key], object_key)
                    elif isinstance(object_[object_key], list):
                        for index, item in enumerate(object_[object_key]):
                            _orderedDict[index] = item
                    else:
                        _orderedDict[object_key] = object_[object_key]

        _json_key(dict_json, None)
        return _orderedDict

    @staticmethod
    def replace_jsonkey(dict_json, k, v):
        def _replace_jsonkey(dic_json, k, v):
            if isinstance(dic_json, dict):
                for key in dic_json:
                    if key == k:
                        dic_json[key] = v
                    elif isinstance(dic_json[key], dict):
                        _replace_jsonkey(dic_json[key], k, v)

        _replace_jsonkey(dict_json, k, v)

    def getMutations(self, data):
        isJson = True
        mutations = {}
        try:
            validjson = json.loads(data)
        except:
            isJson = False
        # 如果validjson解析不出来，则跳过
        if not isJson:
            return

        fuzzjson = JsonFuzzer.json_key(validjson).items()
        fuzzer = BasicTypeFuzzer()
        num = 0
        for k, value in fuzzjson:
            # 遍历payload
            for mut in fuzzer.getMutations(value):
                key = str(k) + str(mut)
                if data.count(str(value)) == 1:
                    dataMutated = data.replace('"' + str(value) + '"', str(mut))
                    # mutations.append(dataMutated)
                    mutations[key] = dataMutated
                elif data.count('"' + str(value) + '"') == 1:
                    dataMutated = data.replace('"' + str(value) + '"', '"' + str(mut) + '"')
                    mutations[key] = dataMutated

        return mutations

    def reset(self):
        return


# 可以规范下导入导出错误
class duplicateOnOff(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        button = self._extender.duplicateOnOff
        if (button.getText() == "Duplicate OFF"):
            self._extender.isDuplicate = True
            button.setText("Duplicate ON ")
        else:
            self._extender.isDuplicate = False
            button.setText("Duplicate OFF")
        return


# clear redis action
class actionRunMessage(ActionListener):
    def actionPerformed(self, e):
        r = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=True)
        listkey = r.keys('*bloomfilter*')
        for key in listkey:
            r.delete(key)
        # 几种弹窗的形式：https://www.cnblogs.com/guohaoyu110/p/6440333.html
        JOptionPane.showMessageDialog(None, "Clear Redis Successfully!")


# 启动线程来完成请求的发送
class buildHttp(threading.Thread):
    def __init__(self, threadid, extender, log, body):
        threading.Thread.__init__(self)
        self.threadid = threadid
        self._extender = extender
        self._log = log
        self._body = body

    # 执行代码放在run中，线程在创建后会直接运行run函数
    def run(self):
        method = self._log._method
        if method == "GET":
            self.FuzzGet()
        elif (method == "POST" or method == "PUT"):
            self.FuzzPost()

    def FuzzGet(self):
        req_url = self._log._url
        request_byte = self._extender._helpers.buildHttpRequest(req_url)
        # self._extender._stdout.println("request:"+self._extender._helpers.bytesToString(request_byte))
        try:
            statusCode = self.makeHttp(request_byte)
            self._extender._stdout.println("Get code:" + str(statusCode))
        except Exception as e:
            print("BuildHttp error", e)

    def FuzzPost(self):
        # 获取list<headers> 和body
        if self._log.headers is None:
            return
        # self._extender._stdout.println(self._body)
        body_byte = self._extender._helpers.stringToBytes(self._body)
        try:
            # self._extender._stdout.println(self._log.headers)
            req = self._extender._helpers.buildHttpMessage(self._log.headers, body_byte)
            statusCode = self.makeHttp(req)
            # self._extender._stdout.println(str(threading.currentThread()) + str(statusCode))
        except Exception as e:
            print("HTTP POST error!", e)

    def makeHttp(self, request):
        httpService = self._log._httpService
        response = self._extender._callbacks.makeHttpRequest(httpService, request)
        resp = response.getResponse()
        if resp:
            responseInfo = self._extender._helpers.analyzeResponse(resp)
            statusCode = responseInfo.getStatusCode()
        else:
            statusCode = 500
        return statusCode


class FieldFocusFoListener(FocusListener):
    def __init__(self, field, hint):
        self.field = field
        self.hint = hint
        self.field.setText(hint)
        self.field.setForeground(Color.GRAY)

    # 获取焦点
    def focusGained(self, e):
        temp = self.field.getText()
        if str(temp) == self.hint:
            self.field.setText("")
            self.field.setForeground(Color.BLACK)

    # 失去焦点
    def focusLost(self, e):
        # 清空会导致用户输入的payload未添加，故这里不做任何处理
        temp = self.field.getText()
        if str(temp) != self.hint:
            self.field.setText(self.hint)
            self.field.setForeground(Color.GRAY)


# options面板增删清
class deletePayloadlist(ActionListener):
    def __init__(self, extender, selectRow, model):
        self._extender = extender
        self.selectRow = selectRow
        self.model = model

    def actionPerformed(self, evt):
        jlist_btn = evt.getActionCommand()

        if jlist_btn == "Add":
            tmp = self._extender.addPayloadField.getText()
            if tmp != "":
                self._extender.payload_lists.add(tmp)
                self.model.fireTableDataChanged()

        elif jlist_btn == "Remove":
            # if self.selectRow == -1:
            # return
            self.selectRow.reverse()
            for i in self.selectRow:
                self._extender._stdout.println(i)
                self._extender.payload_lists.remove(i)
                # 一定要通知数据模型更新数据
                self._extender.payloadmodel.fireTableDataChanged()
        elif jlist_btn == "Clear":
            self._extender.payload_lists.clear()
            # 一定要通知数据模型更新数据
            self.model.fireTableDataChanged()

        elif jlist_btn == "Load ...":
            jfc = JFileChooser()
            jfc.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES)
            jfc.showDialog(JLabel(), None)
            file = jfc.getSelectedFile()
            # 判断文件还是文件夹
            if os.path.isfile(str(file)):
                self._extender.payload_lists.clear()
                p = Payload(str(file))
                for i in p.generator():
                    self._extender.payload_lists.add(i)
                self.model.fireTableDataChanged()
        elif jlist_btn == "Export":
            jfc = JFileChooser()
            jfc.setDialogType(JFileChooser.SAVE_DIALOG)
            jfc.setDialogTitle("Export File")
            option = jfc.showDialog(None, None)
            if option == JFileChooser.APPROVE_OPTION:
                file = jfc.getSelectedFile()
                fos = FileOutputStream(file)

                for i in range(len(self._extender.payload_lists)):
                    payloadout = "\r\n" + str(self._extender.payload_lists.get(i))
                    self._extender._stdout.println(payloadout)
                    fos.write(payloadout)
                fos.close()

        return


# 删除选中的行,最终要删除列表中的实体
class deleteLogtable(ActionListener):
    def __init__(self, extender, row, sign):
        self._extender = extender
        self._row = row
        self.sign = sign
        if sign == "fuzz":
            self._logx = self._extender._fuzz
            self._model = self._extender._fuzzModel
        elif sign == "main":
            self._logx = self._extender._log
            self._model = self._extender._dataModel

    def clearMessage(self, requestView, responseView):
        requestView.setMessage(" ", True)
        # 一直都是空，原因就是processHttpMessage去构造请求了
        responseView.setMessage(" ", False)

    def actionPerformed(self, evt):
        if self.sign == "main":
            self.reqView = self._extender.requestView
            self.respView = self._extender.responseView
        elif self.sign == "fuzz":
            self.reqView = self._extender.requestFuzzView
            self.respView = self._extender.responseFuzzView
        # 通过获取按钮的内容来做相对的响应（https://www.cnblogs.com/dengyungao/p/7525013.html）
        buttonName = evt.getActionCommand()
        self._extender._stdout.println(buttonName)
        if buttonName == "Remove Selected":
            if self._row == -1:
                return
            self._row.reverse()
            for i in self._row:
                self._extender._stdout.println(type(self._row))
                self._logx.remove(i)
                # 一定要通知数据模型更新数据
                self._model.fireTableDataChanged()
                messages = "logx {},fuzz {},log {},row {}".format(self._logx.size(), self._extender._fuzz.size(),
                                                                  self._extender._log.size(), i)
                self._extender._stdout.println(messages)

            # self._extender._stdout.println(type(self._row))
            # self._extender._stdout.println(self._row)
            # 千万不要写_row
            if self._logx.size() == 0:
                self.clearMessage(self.reqView, self.respView)

            # JOptionPane.showMessageDialog(None, "Remove Successfully!")
        # 一定要有二次点击确定,防止误删除
        if buttonName == "Clear All Histroy":
            self._extender._stdout.println(buttonName)
            if self._row == -1:
                return
            isSure = JOptionPane.showMessageDialog(None, "Are you Sure to Clear All Histroy?",
                                                   "Sure",
                                                   JOptionPane.YES_NO_CANCEL_OPTION)
            # self._extender._stdout.println("xxx:" + str(isSure))
            # JOptionPane.YES_OPTION 0
            # 此处有bug,目前无法获取到isSure的正确值
            if isSure == None:
                self._logx.clear()
                self.clearMessage(self.reqView, self.respView)
                self._extender._stdout.println("clear all history:" + str(self._extender._log.size()))
                # 一定要通知数据模型更新数据
                self._model.fireTableDataChanged()

        if buttonName == "Send to Repeater":
            self._extender._stdout.println(buttonName)
            if self._row == -1:
                return

            for i in self._row:
                logEntry = self._logx.get(i)
                self._extender._callbacks.sendToRepeater(logEntry._host, logEntry._port, logEntry._protocol,
                                                         logEntry._requestResponse.getRequest(), str(i))

        if buttonName == "Active Scan":
            self._extender._stdout.println(buttonName)
            if self._row == -1:
                return

            for i in self._row:
                logEntry = self._logx.get(i)
                self._extender._callbacks.doActiveScan(logEntry._host, logEntry._port, logEntry._protocol,
                                                       logEntry._requestResponse.getRequest())

        if buttonName == "Send to Intruder":
            self._extender._stdout.println(buttonName)
            if self._row == -1:
                return
            for i in self._row:
                logEntry = self._logx.get(i)
                self._extender._callbacks.sendToIntruder(logEntry._host, logEntry._port, logEntry._protocol,
                                                         logEntry._requestResponse.getRequest())
        # 有个bug 需要修复，就是获取的值和显示的差别很大（已修复）
        if buttonName == "IntruderFuzz":
            self._extender._stdout.println(buttonName)
            if self._row == -1:
                return
            for i in self._row:
                row = self._extender._fuzz.size()
                # list添加该intruderfuzz 请求
                # self._extender._stdout.println("test:" + str(i) + ":row:" + str(row))
                log = self._extender._log.get(i)
                # self._extender._stdout.println(log._data)
                # 这里开始判断request中是否存在json请求，识别之后再添加list，并插入工具位置，然后再变换payload
                '''
                {"message":"ok","nu":"11111111111","ischeck":"1","com":"yuantong",
                "status":"200","condition":"F00","state":"3",
                "data":[{"time":"2019-11-27 22:21:11","context":"查无结果",
                "ftime":"2019-11-27 22:21:11"}]}
                '''
                if re.search(self._extender.JSON_RECONITION_REGEX, log._data):
                    # json.loads(log._data)
                    # 直接引入会有bug
                    # self._extender._stdout.println(type(log._data))
                    # class org.python.core.PyUnicode转化成dict
                    # 重点Fuzz了
                    # self._extender._stdout.println(log._data)
                    jsonfuzz = JsonFuzzer()
                    # payloads_list=jsonfuzz.getMutations(jsonfuzz.getMutations(log._data).items())
                    # self._extender._stdout.println(jsonfuzz.getMutations(log._data).items())
                    # 记录下最原始fuzz的请求data并做对比
                    log.fuzzpayload = "Origin Request"
                    self._extender._origindata = log._data
                    ii = 0
                    for k, val in jsonfuzz.getMutations(log._data).items():
                        try:
                            # 目前这个方案只能是临时替代，该方案在请求出现异常，会出现不稳定
                            ii = ii + 1
                            self._extender._fuzzkeyx = k
                            self._extender._fuzzActivate = True
                            # self._extender._stdout.println(str(threading.currentThread())+str(self._extender._fuzzkeyx))
                            buildHttp(ii, self._extender, log, val).start()
                        except Exception as e:
                            print("buildhttp is error!", e)

                self._extender._fuzz.add(log)
                # 一定要告知fuzzModel更新了
                self._extender._fuzzModel.fireTableRowsInserted(row, row)
                # self.mainTab.setSelectedIndex(2)
            return


class popmenuListener(MouseAdapter):
    def __init__(self, extender, sign):
        self._extender = extender
        self._sign = sign
        if sign == "fuzz":
            self._table = self._extender.fuzzTable
            self.modelx = self._extender._fuzzModel
        elif sign == "main":
            self._table = self._extender.logTable
            self.modelx = self._extender._dataModel
        elif sign == "payloadlist":
            self._table = self._extender.payloadTable
            self._modelx = self._extender.payloadmodel

    def mouseClicked(self, evt):
        # 右键值为3
        if evt.getButton() == 3:
            if self._sign == "payloadlist":
                # 创建弹窗对象
                mpopMenu = JPopupMenu()
                deleteMenu = JMenuItem("Remove")
                copyMenu = JMenuItem("Copy")
                clearMenu = JMenuItem("Clear")
                mpopMenu.add(deleteMenu)
                mpopMenu.add(copyMenu)
                mpopMenu.add(clearMenu)
                # 通过点击位置找到点击为表格中的行
                _selectedRow = self._table.getSelectedRows()
                # 一定要为按钮添加点击事件
                deleteMenu.addActionListener(
                    deletePayloadlist(self._extender, _selectedRow, self._extender.payloadmodel))
                clearMenu.addActionListener(
                    deletePayloadlist(self._extender, _selectedRow, self._extender.payloadmodel))
                # 一定要指定位置显示弹窗
                mpopMenu.show(self._table, evt.getX(), evt.getY())


            else:
                # 创建弹窗对象
                mpopMenu = JPopupMenu()
                deleteMenu = JMenuItem("Remove Selected")
                repeaterMenu = JMenuItem("Send to Repeater")
                intruderMenu = JMenuItem("Send to Intruder")
                copyMenu = JMenuItem("Copy URL")
                activeMenu = JMenuItem("Active Scan")
                intruderFuzzMenu = JMenuItem("IntruderFuzz")
                clearMenu = JMenuItem("Clear All Histroy")
                mpopMenu.add(deleteMenu)
                mpopMenu.add(repeaterMenu)
                mpopMenu.add(intruderMenu)
                mpopMenu.add(activeMenu)
                mpopMenu.add(intruderFuzzMenu)
                # 添加一条分割符，达到提示的效果
                mpopMenu.addSeparator()
                mpopMenu.add(clearMenu)
                mpopMenu.addSeparator()
                mpopMenu.add(copyMenu)
                # 通过点击位置找到点击为表格中的行
                self._extender._focusedRow = self._table.getSelectedRows()
                # self._extender._stdout.println(self._extender._focusedRow)
                # 一定要为按钮添加点击事件
                deleteMenu.addActionListener(deleteLogtable(self._extender, self._extender._focusedRow, self._sign))
                clearMenu.addActionListener(deleteLogtable(self._extender, self._extender._focusedRow, self._sign))
                repeaterMenu.addActionListener(deleteLogtable(self._extender, self._extender._focusedRow, self._sign))
                intruderMenu.addActionListener(deleteLogtable(self._extender, self._extender._focusedRow, self._sign))
                # deleteMenu.addActionListener()
                activeMenu.addActionListener(deleteLogtable(self._extender, self._extender._focusedRow, self._sign))
                intruderFuzzMenu.addActionListener(
                    deleteLogtable(self._extender, self._extender._focusedRow, self._sign))
                # 一定要指定位置显示弹窗
                mpopMenu.show(self._table, evt.getX(), evt.getY())


class WebFuzz(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self.PAYLOADSS = extender.PAYLOADSS
        self.maxpayloads = 5
        self.numpayloads = 0
        # corups = open('Fuzzing.pay', 'r')
        # self._extender._stdout.println(corups)
        self.PAYLOADS = []
        for line in self.PAYLOADSS:
            # self._extender._stdout.println(line)
            self.PAYLOADS.append(bytearray(line))
        # self._extender._stdout.println(len(self.PAYLOADSS))

    # 决定生成器是否能够提供更多payload
    # boolean
    def hasMorePayloads(self):
        # 如果达到最大次数就返回false退出，但并不是直接退出而是到reset函数，这里reset函数就是清零
        if (self.numpayloads < len(self.PAYLOADS)):
            return True
        else:
            return False

    # 用于获取下一个payload
    def getNextPayload(self, payload):
        # 传进来的参数是payload
        payload = "".join(chr(x) for x in payload)
        payload += self.PAYLOADS[self.numpayloads]
        self.numpayloads += 1
        return payload

    # 重制生成器状态，使下次调用getNextPayload方法时返回第一条payload
    def reset(self):
        self.numpayloads == 0
        return


class IntruderFuzz(ActionListener):
    def __init__(self, extender, selectedMessages, bounds):
        self._extender = extender
        self._selectedMessages = selectedMessages
        self._bounds = bounds

    '''
    Intruder Fuzz
    Command injection
    Path Traversal
    CSV injection
    XML injection
    SQL injection
    Xpath injection
    '''

    def actionPerformed(self, evt):
        # 通过获取按钮的内容来做相对的响应（https://www.cnblogs.com/dengyungao/p/7525013.html）
        buttonName = evt.getActionCommand()
        requestResponse = self._selectedMessages[0]
        httpservice = requestResponse.getHttpService()
        if httpservice.getProtocol() == "https":
            useHttps = True
        else:
            useHttps = False
        request = requestResponse.getRequest()
        insertionOffsets = ArrayList()

        if self._bounds != None:
            # https://portswigger.net/burp/extender/writing-your-first-burp-suite-extension
            insertionOffsets.add(array([self._bounds[0], self._bounds[1]], 'i'))

        if buttonName == "Intruder Fuzz":
            # 拉起主动扫描
            # doActiveScan(String host,int port,boolean useHttps,byte[] request,List<int[]> insertionPointOffsets);
            self._extender._callbacks.doActiveScan(httpservice.getHost(), httpservice.getPort(), useHttps, request,
                                                   insertionOffsets)
        if buttonName == "Command injection":
            pass
        if buttonName == "CSV injection":
            pass
        if buttonName == "XML injection":
            pass
        if buttonName == "SQL injection":
            pass

        if buttonName == "Two URLEncode":
            pass


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory, IScannerCheck,
                   IIntruderPayloadGeneratorFactory):
    # Burp extensions 列表中的扩展名
    _extensionName = "Fuzz 2.0"
    _labelName = "Web Fuzz"
    _mainName = "main"
    _fuzzName = "fuzz"
    JSON_RECONITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

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
        self._fuzz = ArrayList()
        self._lock = RLock()
        self._fuzzkey = {}
        self._fuzzkeyx = ""
        self._fuzzActivate = False
        self._origindata = ""

        # 0.定义burp插件的主界面（上中下三个部分）
        # https: // blog.csdn.net / xietansheng / article / details / 74366517
        self.mainTab = JTabbedPane()
        mainPanel = JPanel()
        mainPanel.setLayout(BorderLayout())
        # createEmptyBorder(int top,int left,int bottom,int right)
        # mainPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5))
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
        self.duplicateOnOff = JButton("Duplicate OFF")
        # 默认值为不开启
        self.isDuplicate = False
        self.duplicateOnOff.addActionListener(duplicateOnOff(self))
        connDb = JButton("ConnDb")
        redisClear = JButton("Redis Clear")
        redisClear.addActionListener(actionRunMessage())
        connDb = JButton("ConnDb")
        scanAll = JButton("Scan All")
        topPane.add(connDb)
        topPane.add(scanAll)
        topPane.add(redisClear)
        topPane.add(self.duplicateOnOff)
        filterPane.add(topPane)
        filterPane.add(selectProxy)
        filterPane.add(selectRepeater)
        filterPane.add(selectIntruder)
        filterPane.add(selectCookies)
        mainPanel.add(filterPane, BorderLayout.PAGE_START)  # 上部分

        # 2.定义log记录组件
        splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)  # 垂直分布
        self._dataModel = TableModel(self, self._log)
        self.logTable = LogJTable(self, self._dataModel, self._mainName)
        # 绑定点击事件
        self.logTable.addMouseListener(popmenuListener(self, self._mainName))

        # 设置列宽
        for i in range(self.logTable.getColumnCount()):
            # python
            tablecolumn = self.logTable.getColumnModel().getColumn(i)
            tablecolumn.setPreferredWidth(self._dataModel.getColumnWidth(i))
        # 设置下水平滚动，垂直滚动ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED,ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        logscrollPane = JScrollPane(self.logTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        splitpane.setDividerLocation(340)
        splitpane.setLeftComponent(logscrollPane)

        # 3.下面组件为request|response显示区域
        # tabs = JTabbedPane(JTabbedPane.TOP)
        requestResponseView = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        requestResponseView.setResizeWeight(0.5)
        requestPanel = JPanel()
        requestPanel.setLayout(BorderLayout())
        responsePanel = JPanel()
        responsePanel.setLayout(BorderLayout())
        '''
         IMessageEditor createMessageEditor(IMessageEditorController contrpoller,
            boolean editable);
        '''
        requestEditor = FuzzEditor(self)
        responseEditor = FuzzEditor(self)
        self.requestView = callbacks.createMessageEditor(requestEditor, False)
        self.responseView = callbacks.createMessageEditor(responseEditor, False)
        # 界面由tabs选项卡改为两开界面(11.26)
        requestPanel.add(self.requestView.getComponent())
        responsePanel.add(self.responseView.getComponent())
        requestResponseView.setLeftComponent(requestPanel)
        requestResponseView.setRightComponent(responsePanel)
        splitpane.setRightComponent(requestResponseView)
        mainPanel.add(splitpane, BorderLayout.CENTER)

        # 4.定义Fuzz记录组件
        fuzzsplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)  # 垂直分布
        self._fuzzModel = TableFuzzModel(self, self._fuzz)
        self.fuzzTable = LogJTable(self, self._fuzzModel, self._fuzzName)
        # 添加渲染器
        try:
            cloumnrenderer = self.fuzzTable.getColumnModel().getColumn(4)
            tcr = FuzzTableCellRenderer(self)
            cloumnrenderer.setCellRenderer(tcr)
        except Exception as e:
            print("CellRenderer error!", e)

        # 设置列宽
        for i in range(self.fuzzTable.getColumnCount()):
            # python
            tablecolumn2 = self.fuzzTable.getColumnModel().getColumn(i)
            tablecolumn2.setPreferredWidth(self._fuzzModel.getColumnWidth(i))
        # 绑定点击事件
        self.fuzzTable.addMouseListener(popmenuListener(self, self._fuzzName))

        # 设置下水平滚动，垂直滚动ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED,ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED
        fuzzscrollPane = JScrollPane(self.fuzzTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                     ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        fuzzsplitpane.setLeftComponent(fuzzscrollPane)

        # 4.下面组件为request|response显示区域
        req_respFuzzView = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        req_respFuzzView.setResizeWeight(0.5)
        requestFuzzPanel = JPanel()
        requestFuzzPanel.setLayout(BorderLayout())
        responseFuzzPanel = JPanel()
        responseFuzzPanel.setLayout(BorderLayout())
        '''
         IMessageEditor createMessageEditor(IMessageEditorController contrpoller,
            boolean editable);
        '''
        requestFuzzEditor = FuzzEditor(self)
        responseFuzzEditor = FuzzEditor(self)
        self.requestFuzzView = callbacks.createMessageEditor(requestFuzzEditor, False)
        self.responseFuzzView = callbacks.createMessageEditor(responseFuzzEditor, False)
        # 界面由tabs选项卡改为两开界面(11.26)
        requestFuzzPanel.add(self.requestFuzzView.getComponent())
        responseFuzzPanel.add(self.responseFuzzView.getComponent())
        req_respFuzzView.setLeftComponent(requestFuzzPanel)
        req_respFuzzView.setRightComponent(responseFuzzPanel)
        fuzzsplitpane.setRightComponent(req_respFuzzView)

        # 初始化话payload yaml
        self.yamlPayload = Payload().readYaml2("Fuzzing.yaml")


        # 初始化读取payload文件
        self.payload_lists = ArrayList()
        corups = open('Fuzzing.pay', 'r')
        # self._stdout.println(corups)
        for line in corups:
            # self._extender._stdout.println(line)
            self.payload_lists.add(line.strip('\n'))

        # 2.3 JList实现增删改
        self.payloadmodel = PayloadModel(self, self.payload_lists)
        self.payloadTable = PayloadTable(self, self.payloadmodel)
        self.payloadTable.getTableHeader().setVisible(False)
        renderer = DefaultTableCellRenderer()
        renderer.setPreferredSize(Dimension(0, 0))
        self.payloadTable.getTableHeader().setDefaultRenderer(renderer)

        # options面板,垂直布局
        optionSpane = JPanel()
        layout = BoxLayout(optionSpane, BoxLayout.Y_AXIS)
        optionSpane.setLayout(layout)

        optionTop = JPanel()
        layout_top = BoxLayout(optionTop, BoxLayout.Y_AXIS)
        optionTop.setLayout(layout_top)
        optionTop.setBorder(BorderFactory.createTitledBorder("Payload List"))
        loadPayload = JButton("Load ...")
        # clearPayload = JButton("Clear")
        exportPayload = JButton("Export")
        addPayload = JButton("Add")
        self.addPayloadField = JTextField()
        # 一定要修复的bug https://blog.csdn.net/andycpp/article/details/1189221?locationNum=5
        self.addPayloadField.setMaximumSize(Dimension(120, 30))
        self.addPayloadField.addFocusListener(FieldFocusFoListener(self.addPayloadField, "Add a new Payload"))
        # 添加监听事件
        self.payloadTable.addMouseListener(popmenuListener(self, "payloadlist"))
        addPayload.addActionListener(deletePayloadlist(self, -1, self.payloadmodel))
        loadPayload.addActionListener(deletePayloadlist(self, -1, self.payloadmodel))
        exportPayload.addActionListener(deletePayloadlist(self, -1, self.payloadmodel))
        # clearPayload.addActionListener(deletePayloadlist(self, -1, self.payloadmodel))

        optionBottom = JPanel()
        layout_bottom = BoxLayout(optionBottom, BoxLayout.X_AXIS)
        optionBottom.setLayout(layout_bottom)
        optionBottom.add(loadPayload)
        optionBottom.add(exportPayload)
        optionBottom.add(addPayload)
        optionBottom.add(self.addPayloadField)

        optionAddPanel = JPanel()
        label = JLabel("""<html>Web Fuzz<br><body><p>A payload in Webfuzz is a source of data.</p></body></html>""")
        optionSplitpane = JSplitPane()
        optionScrollPane = JScrollPane(self.payloadTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                       ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        optionTop.add(optionScrollPane)
        optionTop.add(optionBottom)
        optionSpane.add(optionTop)
        optionAddPanel.add(label)
        optionSplitpane.setDividerLocation(340);
        optionSplitpane.setLeftComponent(optionSpane)
        optionSplitpane.setRightComponent(optionAddPanel)

        self.mainTab.add("Main", mainPanel)
        self.mainTab.add("Fuzz", fuzzsplitpane)
        self.mainTab.add("Options", optionSplitpane)

        # callbacks.registerProxyListener(self)
        # 美容UI
        callbacks.customizeUiComponent(splitpane)
        callbacks.customizeUiComponent(mainPanel)
        callbacks.customizeUiComponent(fuzzsplitpane)
        callbacks.customizeUiComponent(self.mainTab)
        callbacks.customizeUiComponent(self.logTable)
        callbacks.customizeUiComponent(logscrollPane)
        callbacks.customizeUiComponent(optionSplitpane)
        callbacks.customizeUiComponent(requestResponseView)
        # 一定要加ITab,不然没有界面
        callbacks.addSuiteTab(self)
        # 注册httpListener
        callbacks.registerHttpListener(self)
        # 注册扫描
        callbacks.registerScannerCheck(self)
        # payload生成器
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.registerContextMenuFactory(self)
        return

    # 被动扫描（被动-----听！，主动-----搜！）
    def doPassiveScan(self, baseRequestResponse):
        requestscan = self._helpers.analyzeRequest(baseRequestResponse)
        self._stdout.println("PassiveScan")
        return

    '''
    IHttpRequestResponse
    baseRequestResponse,
    IScannerInsertionPoint
    insertionPoint);
    '''

    # 主动扫描
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    # payload生成器的名称
    def getGeneratorName(self):
        return "Web Fuzz"

    # 实例
    def createNewInstance(self, attack):
        return WebFuzz(self, attack)

    # 定义请求、响应中的请求Fuzz
    # IContextMenuInvocation invocation
    def createMenuItems(self, invocation):
        menuList = ArrayList()
        menu = JMenu("Web Fuzz")
        intruderSelected = JMenuItem("Intruder Fuzz")
        commandSelected = JMenuItem("Command injection")
        pathSelected = JMenuItem("Path Traversal")
        csvSelected = JMenuItem("CSV injection")
        xmlSelected = JMenuItem("XML injection")
        sqlSelected = JMenuItem("SQL injection")
        xpathSelected = JMenuItem("Xpath injection")
        twoSelected=JMenuItem("Two URLEncode")
        menu.add(intruderSelected)
        menu.add(commandSelected)
        menu.add(pathSelected)
        menu.add(csvSelected)
        menu.add(xmlSelected)
        menu.add(sqlSelected)
        menu.add(xpathSelected)
        menu.add(twoSelected)
        menuList.add(menu)
        # IHttpRequestResponse[]
        selectedMessagess = invocation.getSelectedMessages()
        # start and end offsets
        bounds = invocation.getSelectionBounds()
        # 判断选中的请求存在，且选中的内容不为空
        # bug 一定要用len() 代替xx.length
        # JOptionPane.showMessageDialog(None, "Select some param to Fuzz!")
        try:
            if bounds[0] == bounds[1]:
                # JOptionPane.showMessageDialog(None, "Select some param to Fuzz!")
                return
        except Exception as e:
            print("bounds", e)

        if (selectedMessagess != None and bounds != None and len(bounds) >= 2):
            self._stdout.println("bounds:" + str(len(bounds)))
            intruderSelected.addActionListener(IntruderFuzz(self, selectedMessagess, bounds))
        else:
            # JOptionPane.showMessageDialog(None, "Select some param to Fuzz!")
            pass
        return menuList

    '''
    void processHttpMessage(int toolFlag,
            boolean messageIsRequest,
            IHttpRequestResponse messageInfo);
    拦截HTTP请求
    '''

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        # scanner 扫描的添加到Fuzz列表中去
        # Proxy Spider Scanner Intruder
        # 判断请求是否是PROXY中的
        if toolFlag == 4 or toolFlag == 32 or toolFlag == 16 or toolFlag == 64 or toolFlag == 1024:
            # 既有响应又有请求，很重要(不然会出现很大的bug)
            if not messageIsRequest:
                # self._stdout.println("Enter print request")
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
                    # self._stdout.println("Url:" + str(url) + "\n" + "".join(newHeaders) + "\n" + bodyStrings)
                    try:
                        if toolFlag == 16 or toolFlag == 1024:
                            self._lock.acquire()
                            try:
                                # fuzzmessage = "key:{},post data:{}".format(self._fuzzkeyx, bodyStrings)
                                # self._stdout.println(str(threading.currentThread())+fuzzmessage)
                                # self._stdout.println(str(bodyStrings)+":"+str(self._origindata))
                                # 对比下原始的请求和bodyStrings差异
                                # bodyStrings="'"+bodyStrings+"'"
                                # originStrings="'"+self._origindata+"'"
                                self._stdout.println(bodyStrings + ":::" + str(self._origindata))
                                diff = self.strDiff(str(bodyStrings), str(self._origindata))
                                # self._stdout.println("diff test:" + diff)
                                row_fuzz = self._fuzz.size()
                                self.fuzzLog = LogEntry(toolFlag, messageInfo, self._helpers, self._callbacks)
                                self._fuzz.add(self.fuzzLog)
                                if self._fuzzActivate:
                                    self.fuzzLog.fuzzpayload = diff
                                    # self._fuzzActivate=False
                                else:
                                    self.fuzzLog.fuzzpayload = ""

                                self._fuzzModel.fireTableRowsInserted(row_fuzz, row_fuzz)
                            finally:
                                self._lock.release()
                        else:
                            self._lock.acquire()
                            row = self._log.size()
                            bloom = BloomFilter()
                            # 解决URL去重，1 布隆过滤器 2 哈希表去重
                            # https://www.cnblogs.com/i-love-python/p/11537720.html
                            isExists = bloom.isContains(str(url))
                            # IHttpRequestResponsePersisted extends IHttpRequestResponse
                            # 重复开关开启且不存在
                            self._stdout.println(str(isExists) + ":" + str(self.isDuplicate))
                            if isExists and self.isDuplicate:
                                pass
                            else:
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

    # Give the new tab a name
    def getTabCaption(self):
        return self._labelName

    def getUiComponent(self):
        return self.mainTab

    '''
    public int getRowCount();
    public int getColumnCount();
    public Object getValueAt(int row, int column);
    '''

    def strDiff(self, modify, origin):
        # print(modify,origin)
        index = -1
        index_ = -1
        for index, val in enumerate(modify):
            if not origin[index] == val:
                break
        diffstrings = modify[index:]
        for index_, val_ in enumerate(diffstrings):
            # print(diffstrings[index_])
            if diffstrings[index_] == '"':
                break

        return diffstrings[:index_]


# 定义jlist
# https://www.javadrive.jp/tutorial/jlist/index14.html
# JList list,Object value,int index,boolean isSelected,boolean cellHasFocus
class JListCellRenderer(ListCellRenderer):
    def __init__(self):

        self.label = JLabel()
        self.label.setOpaque(True)

    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):
        if isSelected:
            print(isSelected)
            self.label.setText("*" + str(value) + "*")
            self.label.setBackground(Color.RED)
        if index % 2 == 0:
            self.setBackground(Color.RED)
        else:
            self.setBackground(Color.BLUE)

        return self.label


# 渲染器
class FuzzTableCellRenderer(TableCellRenderer):
    def __init__(self, extender):
        self._extender = extender
        self.default_renderer = DefaultTableCellRenderer()

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):

        bg = self.default_renderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        # 获取每行的logentry
        LogEntry = self._extender._fuzz.get(row)
        if LogEntry._status is None:
            return

        if (2 <= LogEntry._status / 100 < 3):
            bg.setBackground(Color.GREEN)
        elif (3 <= LogEntry._status / 100 < 4):
            bg.setBackground(Color.YELLOW)
        elif (4 <= LogEntry._status / 100 < 5):
            bg.setBackground(Color.RED)
        elif (5 <= LogEntry._status / 100 < 6):
            bg.setBackground(Color.ORANGE)
        else:
            bg.setBackground(Color.GREY)
        return self.default_renderer


class TableFuzzModel(DefaultTableModel):
    def __init__(self, extender, log):
        self._extender = extender
        self._logx = log

    # # Host URL PAYLOAD Status Length SSL
    def getColumnWidth(self, columnIndex):
        if columnIndex == 1:
            return 120
        if columnIndex == 2:
            return 200
        if columnIndex == 3:
            return 380
        return 60

    def getColumnCount(self):
        return 7

    def getRowCount(self):
        return self._logx.size()

    def getColumnClass(self, columnIndex):
        if columnIndex == 6:
            return Boolean
        return str

    def isCellEditable(self, row, columnIndex):
        return False

    # 设置Fuzz表头
    def getColumnName(self, columnIndex):
        # {# Host URL PAYLOAD Status Length SSL}
        if columnIndex == 0:
            return "#"
        if columnIndex == 1:
            return "Host"
        if columnIndex == 2:
            return "Url"
        if columnIndex == 3:
            return "PAYLOAD"
        if columnIndex == 4:
            return "Status"
        if columnIndex == 5:
            return "Length"
        if columnIndex == 6:
            return "SSL"
        return ""

    def getValueAt(self, row, columnIndex):
        logEntry = self._logx.get(row)
        if columnIndex == 0:
            return logEntry._id
        if columnIndex == 1:
            return logEntry._host
        if columnIndex == 2:
            return logEntry._queryPath
        if columnIndex == 3:
            return logEntry.fuzzpayload
        if columnIndex == 4:
            return logEntry._status
        if columnIndex == 5:
            return "Length"
        if columnIndex == 6:
            return logEntry._protocol
        return ""


# https://docs.oracle.com/javase/7/docs/api/javax/swing/JTable.html
class TableModel(DefaultTableModel):
    def __init__(self, extender, log):
        self._extender = extender
        self._logx = log

    def getColumnWidth(self, columnIndex):
        if columnIndex == 1:
            return 120
        if columnIndex == 4:
            return 380
        return 40

    def getColumnCount(self):
        return 11

    def getRowCount(self):
        # self._extender._stdout.println("test:"+str(self._extender._log.size()))
        return self._logx.size()

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
            return ""
        return ""

    def getValueAt(self, row, columnIndex):
        logEntry = self._logx.get(row)
        if columnIndex == 0:
            return logEntry._id
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
            return logEntry._protocol
        if columnIndex == 9:
            return logEntry._time
        if columnIndex == 10:
            return ""
        return ""


class PayloadModel(DefaultTableModel):
    def __init__(self, extender, log):
        self._extender = extender
        self._logx = log

    def getColumnWidth(self, columnIndex):
        if columnIndex == 0:
            return 60
        return 60

    def getColumnCount(self):
        return 1

    def getRowCount(self):
        # self._extender._stdout.println("test:"+str(self._extender._log.size()))
        return self._logx.size()

    def getColumnClass(self, columnIndex):
        return str

    def isCellEditable(self, row, columnIndex):
        return False

    def getValueAt(self, row, columnIndex):
        logEntry = self._logx.get(row)
        if columnIndex == 0:
            return logEntry
        return ""


class PayloadTable(JTable):
    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)


# Jtable https://www.169it.com/article/12959732718244742024.html
class LogJTable(JTable):
    def __init__(self, extender, model, sign):
        self._extender = extender
        # 代码复用Fuzz Main
        self.sign = sign
        self.setModel(model)

    # 解决界面上请求和响应被选中时实时更新
    def changeSelection(self, row, column, toggle, extend):
        try:
            if self.sign == "main":
                self._logx = self._extender._log
                self.reqView = self._extender.requestView
                self.respView = self._extender.responseView
            elif self.sign == "fuzz":
                self._logx = self._extender._fuzz
                self.reqView = self._extender.requestFuzzView
                self.respView = self._extender.responseFuzzView
            # 获取选中的行的详细请求内容
            logEntity = self._logx.get(row)
            # void setMessage(byte[] message, boolean isRequest);
            # bug 两个选项卡复用
            self.reqView.setMessage(logEntity._requestResponse.getRequest(), True)
            # 一直都是空，原因就是processHttpMessage去构造请求了
            # self._extender._stdout.println("test1:" + str(logEntity._requestResponse.getResponse()))
            try:

                self.respView.setMessage(logEntity._requestResponse.getResponse(), False)
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
        self._id = 1
        if self._requestResponse.getResponse():
            responseInfo = self._helpers.analyzeResponse(self._requestResponse.getResponse())
            self._status = responseInfo.getStatusCode()
            self._mime = responseInfo.getStatedMimeType()
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        self.headers = requestInfo.getHeaders()
        self._method = requestInfo.getMethod()
        self._url = requestInfo.getUrl()
        self.content_type = requestInfo.getContentType()
        # 请求data提取
        bodyoffset = requestInfo.getBodyOffset()
        bodybytes = messageInfo.getRequest()[bodyoffset:]
        # 转化成string
        self._data = self._helpers.bytesToString(bodybytes)
        # 取出path路径
        path = self._url.getPath()
        if self._url.getQuery():
            self._queryPath = str(path + "?" + self._url.getQuery())
        else:
            self._queryPath = str(path)
        self._host = self._url.getHost()
        self._port = self._url.getPort()
        self._time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self._httpService = self._requestResponse.getHttpService()
        if self._httpService.getProtocol() == "https":
            self._protocol = True
        else:
            self._protocol = False
        # 预制为空，只要做了fuzz,才会有
        self.fuzzpayload = ""


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


'''
Redis使用connection pool来管理对一个redis server 的所有连接，
避免每次建立，释放连接的开销，默认，每个Redis实例都会维护一个自己的连接池。
可以直接建立一个连接池，然后作为参数Redis，这样就可以实现多个Redis实例共享一个连接池。
'''


class RedisCase():
    def connection(self, host, port, password, db):
        try:
            pool = redis.ConnectionPool(host=host, port=port, password=password, db=db)
        except Exception as e:
            print("Redis Connection error!", e)
            rediscase = redis.Redis(connection_pool=pool)
        return rediscase


# https://my.oschina.net/u/3264690/blog/857295
class BloomFilter():
    def __init__(self, host='127.0.0.1', port=6379, db=0, blockNum=1, key='bloomfilter'):
        """
        :param host: the host of Redis
        :param port: the port of Redis
        :param db: witch db in Redis
        :param blockNum: one blockNum for about 90,000,000; if you have more strings for filtering, increase it.
        :param key: the key's name in Redis
        """
        try:
            self.server = redis.Redis(host=host, port=port, db=db)
        except Exception as e:
            print("Redis connection error!", e)
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
