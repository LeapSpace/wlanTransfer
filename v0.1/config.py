#!/usr/bin/python
# -*- coding:utf-8 -*-

#服务端监听接口
SERVER_PORT = 11024
FILE_SERVER_PORT = 11025
#接受数据包大小
BUFSIZE = 2048
#每个数据包中数据大小
DATA_BLOCK_SIZE = 2040
#切片大小
BLOCK_SIZE=10*1024*1024
#线程数量
THREAD_COUNT = 5