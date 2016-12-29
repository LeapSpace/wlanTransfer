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

class FileRecvThread(threading.Thread):
	"""docstring for FileRecvThread"""
	def __init__(self, client):
		threading.Thread.__init__(self)
		super(FileRecvThread, self).__init__()
		self.client = client
	def run(self):
		self.packet = self.client.recv(BUFFERSIZE)
		f=open("tmp/"+self.packet, "wb")
		while True:
			data = self.client.recv(BUFFERSIZE)
			if data:
				f.write(data)
			else:
				break
		f.close()
		self.client.close()

class FileRecver(object):
	"""docstring for FileRecver"""
	def __init__(self, tcp_client, filename, file_size, thread_count):
		super(FileRecver, self).__init__()
		self.tcp_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.tcp_sock.bind(("0.0.0.0", SERVER_PORT+1))
		self.tcp_sock.listen(2)
		self.filename = filename
		self.file_size = file_size
		self.tcp_client = tcp_client
		self.thread_count = thread_count

	def run(self):
		threads = []
		while True:
			client, cltadd = self.tcp_sock.accept()
			if client.getpeername()[0]!=self.tcp_client.getpeername()[0]:
				client.close()
			t = FileRecvThread(client)
			threads.append(t)
			t.start()
			if len(threads==self.thread_count):
				for i in xrange(self.thread_count):
					threads[i].join()
				break
		self.tcp_sock.close()
		for i in range(self.thread_count):
			os.popen("cat tmp/%s>>%s" % (i,self.filename))
			os.popen("rm tmp/%s" % i)

class FileSender(object):
	"""docstring for FileSender"""
	def __init__(self, target, filepath, serial_no=None, offset=None,length=None):
		super(FileSender, self).__init__()
		self.target = target
		self.filepath = filepath
		if not offset or offset<0:
			self.offset = 0
			self.length = os.path.getsize(filepath)
		else:
			self.offset = offset
			self.length = length
		if not serial_no:
			serial_no = 0
		self.serial_no = serial_no
		self.offset = offset
		self.client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.client.connect(self.target)
		self.client.send(serial_no)

	def run(self):
		f = open(self.filepath, "rb")
		f.seek(self.offset)
		read_length = 0
		while True:
			left_data_len = self.length-read_length
			if left_data_len>BUFFERSIZE:
				data = f.read(BUFFERSIZE)
			else:
				data = f.read(left_data_len)
			read_length+=len(data)
			self.client.send(data)
			if read_length>=self.length:
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
		self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.sock.bind(("0.0.0.0", SERVER_PORT))
		self.sock.listen(1)
	def close(self):
		self.sock.close()

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
		thread_count = 3
		block_size = int(math.ceil(file_size*1.0/thread_count))
		if resNo==Msg.SenderFileResNo:
			if data=="yes":
				for i in range(thread_count):
					data_left = file_size-(i+1)*block_size
					if data_left>block_size:
						to_send_len = block_size
					else:
						to_send_len = data_left
					FileSender((target[0],SERVER_PORT+1), filepath, i, i*block_size, to_send_len).run()
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
			input_data = raw_input("input:")
			target,filename = input_data.split(" ")
			start_time = time.time()
			tcpServer.send((target,SERVER_PORT),filename)
			print("time cost:"+str(time.time()-start_time))
		else:
			tcpServer.close()
			break
