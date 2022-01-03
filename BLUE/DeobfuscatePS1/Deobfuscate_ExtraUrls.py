#-*- coding : utf-8-*-
# coding:utf-8

import sys
reload(sys)
sys.setdefaultencoding( "utf-8" )

from base64 import b64decode
import zlib,gzip,re

class Deobfuscate_Funcs():
    '''
    解混淆ps1脚本
    '''
    def deczlib_trunc(s):
        '''
        zlib命令行解压
        '''
        ttdata = b64decode(s[:len(s) - len(s)%4])
        n = len(ttdata)*3
        while n > 0:
            try:
                zlibobj = zlib.decompressobj(-zlib.MAX_WBITS)
                return zlibobj.decompress(ttdata, n)
            except Exception as e:
                n -= 5

    def decgzip_trunc(s):
        '''
        gzip命令行解压
        '''
        out = ''
        ttdata = b64decode(s[:len(s) - len(s)%4])
        obj = gzip.GzipFile(fileobj=gzip.io.BytesIO(ttdata))
        while True:
            try:
                tmp = obj.read(2)
                if not tmp: return out
                out += tmp
            except Exception as e:
                return out

    def __init__(self, debug=0):
        self.debug = debug
    
    def isBase64(self, str):
        '''
        字符串是否为 Base64 格式
        '''
        if re.match('[a-zA-Z0-9]{40,}', str):
            return True
        return False

    urlExtractExp = '[A-Z]{3,5}://[-\w]+(?:\.\w[-\w]*)+(?::\d+)?(?:/[^.!,?"<>\[\]{}\s]*(?:[.!,?]+[^.!,?"<>\[\]{}\s]+)*)?'
    urlReExp = re.compile(urlExtractExp, flags = re.I)

    def CommonSubStr(self, ls):
        '''
        寻找字符串列表中的第一个同偏移公共子字符串
        '''
        if self.debug: print "func CommonSubStr:ls::",ls
        maxlen = len(ls[0])
        for e in ls[1:]:
            maxlen = min(len(e), maxlen)
        key = ''
        for i in range(maxlen):
            cnt = 0
            for e in ls[1:]:
                if ls[0][i] != e[i]:
                    break
                cnt += 1
            if cnt+1 == len(ls):
                key += ls[0][i]
        if self.debug: print "func CommonSubStr:key::",key
        return key

    def getEmotetDeobReplaceKey(self, t):
        '''
        获取Emotet解混淆关键字符串
        '''
        ls = re.findall('https?:([^@*!]+)', t, flags = re.I)
        if ls:
            key = self.CommonSubStr(ls)
            if self.debug : print "func getEmotetDeobReplaceKey:key::",key
            ll = len(key)
            if key and key[:ll/2] == key[ll/2:]:
                return (key[:ll/2],'/')
        # 替换http
        ls = re.findall('[@\*!]([^@\*!]+):', t, flags = re.I)
        if ls:
            key = self.CommonSubStr(ls)
            if key: return (key, 'http')
        # 
        return None

    def stringReplace(self, s):
        '''
        去除字符串拼接混淆
        
        '''
        s = s.replace('(', '').replace(')', '').replace('+', '').replace('\'', '').replace('\"', '').replace('[', '').replace(']', '').replace(' ', '').replace('`', '').replace('|', ' ').replace('^', '')
        # emotet 字符串替换
        if len(s.split('@')) > 3 or len(s.split('*')) > 3  or len(s.split('!')) > 3:
            key = None
            try:
                key = self.getEmotetDeobReplaceKey(s)
            except Exception: 
                if self.debug: print "get key error throwed !!"
                key = None
            if self.debug: print 'func stringReplace:key::',key
            if key: s = s.replace(key[0], key[1])
        # url分割
        s = re.sub(r'http(s?:)', r' http\1', s, flags = re.I)
        # s = s.replace('http', ' http')
        s = re.sub('''\.replace|\.trim-split|\.split''', ' ',s, flags = re.I)
        # s = re.sub('.trim-split', ' ', s, flags = re.I)    # 去除运算符
        if self.debug: print 'func stringReplace:s::',s
        return s

    def Deobfuscate(self, s):
        '''
        解混淆字符串，提取url
        返回值：url元素集
        '''
        text = ''
        for ele in s.split(' '):
            if self.isBase64(ele):
                tmp = ''
                try:
                    tmp = b64decode(ele)[::2]
                except Exception: pass
                if tmp:
                    if self.debug: print 'func Deobfuscate:tmp::',tmp
                    text += '\n' + tmp
        s = re.sub("(\"|')\s*(\+|,)\s*('|\")", '', s)     # 替换拼接符
        if text == '':
            text = s.replace(' ', '\n')
        if self.debug: print 'func Deobfuscate:text::',text
        res = self.urlReExp.findall(self.stringReplace(text))
        if self.debug: print 'func Deobfuscate:res::',res
        if res:
            for ii in range(len(res)):
                temp = re.findall('[A-Z]{3,5}://[^!,?;"<>\[\]{}\s]+', res[ii], flags = re.I)
                if temp: res[ii] = temp[0].strip("@*!")
        return set(res)

