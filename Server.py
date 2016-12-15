#!/usr/bin/python
# -*- coding:utf-8 -*-

import threading
import Queue
import socket
import struct
import time,sys,os,math
from config import *
from Msg import *
from Scanner import *

class TCPServer(object):
	def __init__(self, port, permitHost=None):
		self.port = port
		self.permitHost = permitHost
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(("0.0.0.0", port))
		self.sock.listen(1)
	def run(self):
		print("listener started")
		while True:
			client, cltadd = self.sock.accept()
			if self.permitHost!=None and client.getpeername()!=self.permitHost:
				client.close()
			TCPListener(client).start()

class TCPListener(threading.Thread):
	"""docstring for Listener"""
	def __init__(self, client):
		threading.Thread.__init__(self)
		self.client = client

	def run(self):
		try:
			while True:
				data = self.client.recv(BUFSIZE)
				if(data):
					reqNo,data=struct.unpack(Msg.MSG_FMT,data)
					if reqNo==Msg.ScanReqNo:
						self.client.send(struct.pack(Msg.MSG_FMT, Msg.ScanResNo, socket.gethostname()))
				else:
					break
		except Exception as e:
			raise e
		else:
			pass
		finally:
			self.client.close()


class FileRecv(object):
	"""docstring for FlieRecv"""
	def __init__(self, host,filename,fileSize):
		super(FileRecv, self).__init__()
		self.host = host
		self.filename = filename
		fileSize = fileSize.strip("\0")
		self.fileSize = int(fileSize)
		self.ports = []
		self.pids = Queue.Queue(10)

	def getPorts(self):
		return self.ports


	def run(self):
		blockCount = int(math.ceil(self.fileSize*1.0/BLOCK_SIZE))
		serverCount = blockCount
		if serverCount>10:
			serverCount = 10
		for x in xrange(1, serverCount+1):
			pid = os.fork()
			if pid==0:
				tcp=TCPFileServer(SERVER_PORT+x, 
					self.host, 
					self.filename,
					blockCount,
					self.pids,
					callback=killServer)
				tcp.run()

class TCPFileServer():
	"""docstring for TCPFileServer"""
	def __init__(self, port, permitHost, filename, blockCount, pidQueue, callback):
		self.port = port
		self.pidQueue = pidQueue
		self.blockCount = blockCount
		self.filename = filename
		self.permitHost = permitHost
		self.callback = callback
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(("0.0.0.0", port))
		self.sock.listen(1)
		self.pidQueue.put(os.getpid())

	def run(self):
		#print "receiver server wake up"
		while True:
			try:
				client, cltadd = self.sock.accept()
				if client.getpeername()[0] != self.permitHost:
					client.close()
					continue
				TCPFileListener(self.sock,
					client,
					self.filename,
					self.pidQueue,
					self.blockCount,
					self.callback).start()
			except Exception as e:
				raise e

class TCPFileListener(threading.Thread):
	"""docstring for TCPFileListener"""
	def __init__(self, sockServer, client, filename, pidQueue, blockCount,callback):
		threading.Thread.__init__(self)
		self.sockServer = sockServer
		self.client = client
		self.pidQueue = pidQueue
		self.filename = filename
		self.callback = callback
		self.blockCount = blockCount
	def run(self):
		fdata = data = ""
		read_size = BUFSIZE
		while True:
			try:
				data += self.client.recv(read_size)
				if(data):
					data_length = len(data)
					if data_length!=BUFSIZE:
						read_size = BUFSIZE-data_length
					else:
						read_size = BUFSIZE
						block, size, mdata, isEnd = struct.unpack(Msg.MSG_DATA_FMT,data)
						data = ""
						fdata+=mdata[:size]
						if isEnd==1:
							f=open("tmp/%s" % block,"wb")
							f.write(fdata)
							f.close()
							fdata = ""
							# detect if translation is over
							i = 0
							for f in os.listdir("tmp"):
								i+=1
							print("process: %s%%"%i*1.0/self.blockCount)
							if i==self.blockCount:
								os.popen("echo ''>%s" % self.filename)
								for x in range(1,self.blockCount+1):
									os.popen("cat tmp/%s>>%s" % (x,self.filename))
									os.popen("rm tmp/%s" % x)
								self.client.close()
								self.sockServer.shutdown(2)
								self.sockServer.close()
								self.callback(self.pidQueue)
								break
							fdata=""
			except Exception as e:
				raise e
		print("process end.")


def killServer(queue):
	while True:
		if queue.qsize()<=0:
			break
		pid = queue.get()
		ss=os.popen("kill -9 %s"%pid).readlines()
	'''
	TODO:
	deal with the problem
	Here is some problem.
	del the zhushi, you'll find it.
	'''
	#print "callback done."



class FileSender(object):
	"""docstring for FileSender"""
	def __init__(self, target, filename):
		super(FileSender, self).__init__()
		self.target = target
		self.filename = filename
		if not os.path.exists(filename):
			print(filename+" not exists.")
			os._exit(0)

		self.fileSize = os.path.getsize(filename)
		self.blockCount = int(math.ceil(self.fileSize*1.0/BLOCK_SIZE))
		self.serverCount = self.blockCount
		self.blockQueue = Queue.Queue(self.blockCount)
		if self.blockCount>10:
			self.serverCount = 10
		self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.client.connect((target, SERVER_PORT-1))
		self.client.send(struct.pack(Msg.MSG_FMT,Msg.SenderFileReqNo,"%s\n%s\n%s"%(socket.gethostname(),filename.split("/")[-1],self.fileSize)))
		while True:
			try:
				data = self.client.recv(BUFSIZE)
				if (data):
					resNo,data = struct.unpack(Msg.MSG_FMT,data)
					data=data.strip("\0")
					if resNo==Msg.SenderFileResNo:
						if data=="yes":
							self.client.close()
							self.trySend(target,filename)
							break
						else:
							print("target deny to accept!")
							break
					else:
						continue
			except Exception as e:
				print("data unpack error!")
				raise e
				break

	def trySend(self,target,filename):
		for i in range(1,self.blockCount+1):
			self.blockQueue.put((i,(i-1)*BLOCK_SIZE))
		time.sleep(1)
		for x in range(1,self.serverCount+1):
			try:
				client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				client.connect((self.target, SERVER_PORT+x))
				FileSendWorker(client, self.blockQueue, self.filename).start()
			except Exception as e:
				raise e

class FileSendWorker(threading.Thread):
	"""docstring for FileSendWorker"""
	def __init__(self, client,blockQueue,filename):
		threading.Thread.__init__(self)
		self.client = client
		self.blockQueue = blockQueue
		self.filename = filename
		self.file = open(filename, "rb")

	def run(self):
		while True:
			print self.blockQueue.qsize()
			if self.blockQueue.qsize()<=0:
				self.client.close()
				break
			block,offset = self.blockQueue.get()
			self.file.seek(offset)
			data = self.file.read(BLOCK_SIZE)
			tmp = 0
			isEnd = 0
			data_size = len(data)
			while True:
				end = tmp+DATA_BLOCK_SIZE
				tmp_data = data[tmp:end]
				if not tmp_data:
					break
				if end>=data_size:
					isEnd = 1
				send = struct.pack(Msg.MSG_DATA_FMT,block,len(tmp_data),tmp_data,isEnd)
				if 2048!=len(send):
					print block,offset
				self.client.send(struct.pack(Msg.MSG_DATA_FMT,block,len(tmp_data),tmp_data,isEnd))
				tmp = end

if __name__ == "__main__":
	pid = os.fork()
	if pid==0:
		tcpServer = TCPServer(SERVER_PORT)
		tcpServer.run()
	time.sleep(1)
	while True:
		print("1. scan wlan hosts;\n2. send file to one host;\n3. waiting for receiving file\n\n")
		choice = raw_input("please input your choice:")
		choice = int(choice)
		if choice not in (1,2,3):
			print("input error!")
		else:
			if choice ==1:
				scanner = Scanner(10)
				wlanHosts = scanner.run()
				print("\n\n")
				for host in wlanHosts:
					print(host['host']+"----"+host['hostname'])
				print("\n\n")
			elif choice==2:
				target_file = raw_input("please input the host and file you want to send\n.e.g:192.168.1.110 test.txt\n")
				target,filename = target_file.split(" ")
				fileSender = FileSender(target, filename)
			else:
				print("waiting for someone sending file ...")
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				sock.bind(("0.0.0.0", SERVER_PORT-1))
				sock.listen(1)
				state = False
				while True:
					client, cltadd = sock.accept()
					while True:
						try:
							data = client.recv(BUFSIZE)
							if(data):
								reqNo,data=struct.unpack(Msg.MSG_FMT,data)
								if reqNo==Msg.SenderFileReqNo:
									hostname,filename,fileSize = data.strip().split("\n")
									yesOrNo = raw_input(client.getpeername()[0]+":"+hostname+" wants to send "+filename+" to you,do you want it?yes or no:").lower()
									if yesOrNo=="yes" or yesOrNo=="y":
										fileRecv = FileRecv(client.getpeername()[0],filename,fileSize)
										fileRecv.run()
										client.send(struct.pack(Msg.MSG_FMT, Msg.SenderFileResNo, "yes"))
										client.close()
									else:
										client.send(struct.pack(Msg.MSG_FMT, Msg.SenderFileResNo, "no"))
									client.close()
									state = True
									break
								else:
									continue
						except Exception as e:
							raise e
						else:
							pass
						finally:
							pass
					if state:
						break
				try:
					sock.shutdown(2)
					sock.close()
				except Exception as e:
					raise e


	#time.sleep(0)
	# pid = os.fork()
	# if pid==0:
