#!/usr/bin/python
# -*- coding:utf-8 -*-

class Msg(object):
	'''msg type'''

	ScanReqNo = 100100
	ScanResNo = 100101

	SenderFileReqNo = 100102
	SenderFileResNo = 100103

	MSG_FMT = "<I128s"	#ScanReqNo/hi
	MSG_SEND_REQ_FMT = "<I128s"	#SenderFileReqNo/Space-PC\nFilename/fileSize
	MSG_SEND_RES_FMT = "<I128s"	#SenderFileResNo/yes or no

	DATA_FMT = '''

DATA_START>>>%d|%sDATA_END<<<

'''

if __name__ == "__main__":
	pass