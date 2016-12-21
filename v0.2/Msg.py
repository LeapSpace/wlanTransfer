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
	'''
	block
	current_size
	data
	is_current_block_end
	'''
	MSG_DATA_FMT = "<IH2040sH"

if __name__ == "__main__":
	pass