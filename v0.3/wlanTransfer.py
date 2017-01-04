import socket,struct
import os,sys,math,time,re
import Queue
import threading
import struct
import shutil

SERVER_PORT = 11024

BUFFERSIZE = 1024
BLOCK_SZIE = 10*1024*1024#10M
CUT_SIZE = 1016
SPEED = 100*1024*1024#100M/s

class Msg(object):
	'''msg type'''

	ScanReqNo = 100100
	ScanResNo = 100101

	SenderFileReqNo = 100101
	SenderFileResNo = 100102

	#msgNo|data
	MSG_FMT = "<I128s"

	#block|cut|cut_count|cut_size|data
	DATA_FMT = "<HHHH1016s"

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

class FileRecver(object):
	"""docstring for FileRecver"""
	def __init__(self, tcp_client, filename, file_size):
		super(FileRecver, self).__init__()
		self.tcp_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.tcp_sock.bind(("0.0.0.0", SERVER_PORT+1))
		self.tcp_sock.listen(2)
		self.filename = filename
		self.file_size = file_size
		self.tcp_client = tcp_client

	def run(self):
		while True:
			client, cltadd = self.tcp_sock.accept()
			if client.getpeername()[0]!=self.tcp_client.getpeername()[0]:
				client.close()
			f = open(self.filename, "wb")
			while True:
				data = client.recv(BUFFERSIZE)
				if data:
					f.write(data)
				else:
					break
			f.close()
			client.close()
			break
		self.tcp_sock.close()

class FileSender(object):
	"""docstring for FileSender"""
	def __init__(self, target, filepath):
		super(FileSender, self).__init__()
		self.target = target
		self.filepath = filepath
		self.client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.client.connect(self.target)

	def run(self):
		f = open(self.filepath, "rb")
		while True:
			data = f.read(BUFFERSIZE)
			if data:
				self.client.send(data)
			else:
				break
		self.client.close()

class ScanServer(object):
	def __init__(self, port, permitHost=None):
		self.port = port
		self.permitHost = permitHost
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(("0.0.0.0", port))
		self.sock.listen(5)
	def run(self):
		while True:
			client, cltadd = self.sock.accept()
			if self.permitHost!=None and client.getpeername()[0]!=self.permitHost:
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
				data = self.client.recv(BUFFERSIZE)
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

class TCPServer(object):
	"""docstring for TCPServer"""
	def __init__(self):
		super(TCPServer, self).__init__()
		time.sleep(0.1)
		self.hostname = socket.gethostname()
		self.ip = self.getSelfIp()
		pid = os.fork()
		if pid==0:
			scanServer = ScanServer(SERVER_PORT-1)
			scanServer.run()
		else:
			self.pid=pid
		self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.sock.bind(("0.0.0.0", SERVER_PORT))
		self.sock.listen(1)
	def close(self):
		self.sock.close()
		try:
			os.kill(self.pid, signal.SIGKILL)
		except Exception as e:
			raise e

	def receive(self):
		print("waiting for someone sending file ...")
		self.client, cltadd = self.sock.accept()
		data = self.client.recv(BUFFERSIZE)
		reqNo,data=struct.unpack(Msg.MSG_FMT,data)
		if reqNo==Msg.SenderFileReqNo:
			hostname,filename,fileSize = data.strip().split("\n")
			fileSize = fileSize.strip("\0")
			yesOrNo = raw_input(self.client.getpeername()[0]+"---"+hostname+" wants to send you <<"+filename+">>,\ndo you want it?yes or no:").lower()
			if yesOrNo=="yes" or yesOrNo=="y":
				self.client.send(struct.pack(Msg.MSG_FMT, Msg.SenderFileResNo, "yes"))
				FileRecver(self.client,filename,int(fileSize)).run()
				self.client.close()
			else:
				self.client.send(struct.pack(Msg.MSG_FMT, Msg.SenderFileResNo, "no"))
				self.client.close()
	def scan(self):
		scanner = Scanner(5)
		wlanHosts = scanner.run()
		print("\n")
		for w in wlanHosts:
			print(w)
		print("\n")

	def getHostname(self):
		return self.hostname

	def getSelfIp(self):
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

	def send(self, target, filepath):
		'''
		.e.g:
		target = ("192.168.1.168",8080)
		'''
		if not os.path.exists(filepath):
			print("file not exists")
			return
		file_size = os.path.getsize(filepath)
		filename = filepath.split(os.sep)[-1]
		client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		client.connect(target)
		client.send(struct.pack(Msg.MSG_FMT,Msg.SenderFileReqNo,self.hostname+"\n"+filename+"\n"+str(file_size)))
		data = client.recv(BUFFERSIZE)
		resNo,data = struct.unpack(Msg.MSG_FMT,data)
		data=data.strip("\0")
		if resNo==Msg.SenderFileResNo:
			if data=="yes":
				FileSender((target[0],SERVER_PORT+1), filepath).run()
				client.close()
				#TODO:sendfile
				return
			else:
				print("target deny to accept!")
				return

if __name__ == "__main__":
	tcpServer = TCPServer()
	while True:
		print("1. scan\n2. wait for file\n3. send file to someone\n4. quit\n")
		select = raw_input("what do you want:")
		if not select.isdigit() or select not in ("1","2","3","4"):
			print("input error!")
			continue
		select = int(select)
		if select==1:
			tcpServer.scan()
		elif select==2:
			tcpServer.receive()
		elif select==3:
			print("please input target and file you want to send.\n")
			print("e.g.: 192.168.1.181 /Users/space/Downloads/rockyou.txt\n")
			input_data = raw_input("input:").strip()
			target,filename = input_data.split(" ")
			start_time = time.time()
			tcpServer.send((target,SERVER_PORT),filename)
			print("time cost:"+str(time.time()-start_time))
		else:
			tcpServer.close()
			break
