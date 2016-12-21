#!/usr/bin/python
# -*- coding:utf-8 -*-

import threading
import Queue
import socket
import struct
import time,sys,os
from Msg import *

class Scanner():
	hostname = ""
	ip = ""
	'''Scan server in wlan'''
	def __init__(self, maxThreads=10):
		self.maxThreads = maxThreads
		self.queue = Queue.Queue(255)
		self.threads = []
		self.wlanHostQueue = Queue.Queue(255)

	def run(self): 
		global wlanHost
		self.initQueue()
		self.initThreads()

		for thr in self.threads:
			thr.join()
		print "scan process end:"
		wlanHost = []
		while self.wlanHostQueue.qsize()>0:
			wlanHost.append(self.wlanHostQueue.get())
		return wlanHost

	def initQueue(self):
		partIp = ".".join(Scanner.getSelfIp().split(".")[:3])
		for i in range(2,255):
			self.queue.put(partIp+"."+str(i))

	def initThreads(self):
		for i in range(self.maxThreads):
			self.threads.append(ScanHost("thread-"+str(i),self.queue, self.wlanHostQueue))

	@staticmethod
	def getHostname():
		Scanner.hostname = socket.gethostname()
		return Scanner.hostname

	@staticmethod
	def getSelfIp():
		ip = ""
		if sys.platform=="darwin" or sys.platform.find("linux")>-1:
			ip = os.popen("ifconfig|grep 'inet '|grep -v '127.0.0.1'|awk -F 'inet ' '{print $2}'|cut -d ' ' -f1|head -n1").readline().strip()
		else:
			try:
				ip = socket.gethostbyname(socket.gethostname())
			except:
				s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				s.connect(("baidu.com",80))
				ip = s.getsockname()[0]
				s.close()
		return ip


class ScanHost(threading.Thread):
	'''scan single host'''
	def __init__(self, threadname, queue, wlanHostQueue):
		threading.Thread.__init__(self)
		self.threadname = threadname
		self.queue = queue
		self.wlanHostQueue = wlanHostQueue
		self.start()

	def run(self):
		while True:
			if self.queue.qsize()<=0:
				break
			host = self.queue.get()
			try:
				client = socket.create_connection((host, 11023), 0.5)
				client.settimeout(0.5)
				client.send(struct.pack(Msg.MSG_FMT,Msg.ScanReqNo,"hi"))
				data = client.recv(1024)
				resNo,data = struct.unpack(Msg.MSG_FMT,data)
				if resNo==Msg.ScanResNo:
					self.wlanHostQueue.put({"host":host,"hostname":data.strip("\0")})
				client.close()
			except Exception as e:
				pass

if __name__ == "__main__":
	scanner = Scanner(10)
	wlanHosts = scanner.run()
	print wlanHost
	#print(Msg.getScanReqData())
	# tcpServer = TCPServer(SERVER_PORT)
	# tcpServer.start()
	# scanner = Scanner(10)
	# scanner.run()