import socket,struct
import os,sys,math,time
import Queue
import shutil

SERVER_PORT = 11024

BUFFERSIZE = 1024
BLOCK_SZIE = 10*1024*1024#10M
CUT_SIZE = 1016
SPEED = 100*1024*1024#100M/s

class Msg(object):
	'''msg type'''

	SenderFileReqNo = 100101
	SenderFileResNo = 100102

	#msgNo|data
	MSG_FMT = "<I128s"

	#block|cut|cut_count|cut_size|data
	DATA_FMT = "<HHHH1016s"

class FileRecver(object):
	"""docstring for FileRecver"""
	def __init__(self, tcp_client, filename, file_size):
		super(FileRecver, self).__init__()
		self.udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		self.udp_sock.bind(("0.0.0.0", SERVER_PORT))
		self.filename = filename
		self.block_count = math.ceil(file_size*1.0/BLOCK_SZIE)
		self.block_cuts = {}
		self.block_set = set()

	def run(self):
		while True:
			data,cltadd = self.udp_sock.recvfrom(BUFFERSIZE)
			if cltadd[0]!=tcp_client.getpeername()[0]:
				continue
			if not data:
				continue
			block, cut, cut_count, cut_size, fdata = struct.unpack(Msg.DATA_FMT,data)
			if block==0 and cut==0 and cut_count==0 and cut_size==0:
				break
			self.udp_sock.sendto(cut,cltadd)
			self.block_cuts[cut] = fdata[:cut_size]
			# wait current block transfer complete
			if block not in self.block_set and len(self.block_cuts)==cut_count:
				tempfile = open("tmp/%s" % block, "wb")
				for i in range(cut_count):
					tempfile.write(self.block_cuts[i])
				tempfile.close()
				self.block_cuts = {}
				self.block_set.add(block)
				if len(self.block_set)==self.block_count:
					os.popen("touch %s" % self.filename)
					for i in range(self.block_count):
						os.popen("cat tmp/%s>>%s" % (x,self.filename))
						os.popen("rm tmp/%s" % x)
					break
		self.udp_sock.close()

class FileSender(object):
	"""docstring for FileSender"""
	def __init__(self, target, filepath):
		super(FileSender, self).__init__()
		self.target = target
		self.filepath = filepath
		self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		self.sock.settimeout(0.01)

	def run(self):
		block = 0
		f = open(filepath, "rb")
		while True:
			offset = (block-1)*BUFFERSIZE
			f.seek(offset)
			block_data = f.read(BLOCK_SZIE)
			cut = 0
			cut_count = math.ceil(len(block_data)*1.0/CUT_SIZE)
			to_send_cuts = [i for i in range(cut_count)]
			send_out_unconfirm_cuts = set()
			check = 0
			while len(to_send_cuts)>0:
				#data in transfering > speed * time. wait for server confirm
				if len(send_out_unconfirm_cuts)*CUT_SIZE>(SPEED*0.01):
					if check%100==0:
						print("target server die")
						break
					try:
						recv_data = self.sock.recvfrom(BUFFERSIZE)
						check = 0
						if (recv_data) and recv_data.isdigit():
							send_out_cut = int(recv_data)
							if send_out_cut in to_send_cuts:
								to_send_cuts.remove(send_out_cut)
							if send_out_cut in send_out_unconfirm_cuts:
								send_out_unconfirm_cuts.remove(send_out_unconfirm_cuts)
					except:
						check+=1
					continue
				#send data
				cut = to_send_cuts[0]
				del to_send_cuts[0]
				cut_offset = cut*CUT_SIZE
				cut_data = block_data[cut_offset:cut_offset+CUT_SIZE]
				send_data = struct.pack(Msg.DATA_FMT, block,cut, cut_count, len(cut_data), cut_data)
				self.sock.sendto(send_data, self.target)
				send_out_unconfirm_cuts.add(cut)
				to_send_cuts.append(cut)
				#try to receive data from server
				try:
					recv_data = self.sock.recvfrom(BUFFERSIZE)
					if (recv_data) and recv_data.isdigit():
						send_out_cut = int(recv_data)
						if send_out_cut in to_send_cuts:
							to_send_cuts.remove(send_out_cut)
						if send_out_cut in send_out_unconfirm_cuts:
							send_out_unconfirm_cuts.remove(send_out_unconfirm_cuts)
				except Exception as e:
					pass



class UDPServer(object):
	"""docstring for UDPServer"""

	sock = None
	client = None

	def __init__(self):
		super(UDPServer, self).__init__()

	@staticmethod
	def init():
		UDPServer.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		UDPServer.client = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		UDPServer.client.settimeout(0.01)
		UDPServer.sock.bind(("0.0.0.0",SERVER_PORT-1))

	@staticmethod
	def run():
		if not UDPServer.sock:
			UDPServer.init()
		while True:
			data,cltadd = UDPServer.sock.recvfrom(BUFFERSIZE)
			UDPServer.sock.sendto("hi",cltadd)

	@staticmethod
	def active_check(target):
		if not UDPServer.sock:
			UDPServer.init()
		i=0
		active = False
		while i<3:
			UDPServer.client.sendto("hi",target)
			try:
				data,cltadd = UDPServer.client.recvfrom(BUFFERSIZE)
				active = True
				break
			except:
				i+=1
				continue
		return active



class TCPServer(object):
	"""docstring for TCPServer"""
	def __init__(self):
		super(TCPServer, self).__init__()
		pid = os.fork()
		if pid==0:
			udp_server = UDPServer()
			udp_server.run()
		else:
			self.udp_server_pid=pid
		time.sleep(0.1)
		self.hostname = socket.gethostname()
		self.ip = self.getSelfIp()
		self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.sock.bind(("0.0.0.0", SERVER_PORT))
		self.sock.listen(1)
	def receive(self):
		print("waiting for someone sending file ...")
		self.client, cltadd = self.sock.accept()
		reqNo,data=struct.unpack(Msg.MSG_FMT,data)
		if reqNo==Msg.SenderFileReqNo:
			hostname,filename,fileSize = data.strip().split("\n")
			yesOrNo = raw_input(client.getpeername()[0]+"---"+hostname+" wants to send you <<"+filename+">>,\ndo you want it?yes or no:").lower()
			if yesOrNo=="yes" or yesOrNo=="y":
				self.client.send(struct.pack(Msg.MSG_FMT, Msg.SenderFileResNo, "yes"))
				FileRecver(self.client,filename,fileSize).run()
				self.client.close()
			else:
				self.client.send(struct.pack(Msg.MSG_FMT, Msg.SenderFileResNo, "no"))
				self.client.close()
	def scan(self):
		partIp = ".".join(self.ip.split(".")[:3])
		scan_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		scan_sock.settimeout(0.01)
		for x in range(2,255):
			scan_sock.sendto("hi",(partIp+"."+str(x),SERVER_PORT-1))

		for i in range(2,255):
			try:
				res,addr = scan_sock.recvfrom(BUFFERSIZE)
				print addr,res
			except Exception as e:
				pass

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
		client.send(Msg.MSG_FMT,Msg.MSG_FMT,Msg.SenderFileReqNo,"hostname\n"+filename+"\n"+str(file_size))
		data = client.recv(BUFFERSIZE)
		resNo,data = struct.unpack(Msg.MSG_FMT,data)
		data=data.strip("\0")
		if resNo==Msg.SenderFileResNo:
			if data=="yes":
				FileSender(target, filepath).run()
				client.close()
				#TODO:sendfile
				return
			else:
				print("target deny to accept!")
				return

if __name__ == "__main__":
	tcpServer = TCPServer()
	while True:
		print("1. scan\n2. wait for file\n3. send file to someone\n")
		select = raw_input("what do you want:")
		if not select.isdigit() or select not in ("1","2","3"):
			print("input error!")
			continue
		select = int(select)
		if select==1:
			tcpServer.scan()
		elif select==2:
			tcpServer.receive()
		else:
			print("please input target and file you want to send.\n")
			print("e.g.: 192.168.1.181 /var/log/test.log\n")
			input_data = raw_input("input:")
			target,filename = input_data.split(" ")
			tcpServer.send((target,SERVER_PORT),filename)
