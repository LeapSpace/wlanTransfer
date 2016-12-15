##多个TCP连接传输数据

1. client端发出请求：发送文件｛SenderFileReqNo\nhostname\nFilename/fileSize｝

2. server端响应client请求：返回server yes or no

3. client将文件切片并发送：接到server返回的端口号后，将切片的文件放入队列，按照端口数量，启动相应数量的文件发送client，并从队列中取出切片数据，发送数据包格式 "IH2040sH"(分别代表：当前切片、当前数据包大小、数据、当前切片是否结束)



##切片策略

1. 小于BLOCK_SIZE不切
2. BLOCK_SIZE一片,
3. 每个切片格式：前2个字节代表切片顺序，后边为数据包

##Usage（python2.*）:

    	python Server.py

1. 启动、scan

2. scan

3. 列出局域网主机

4. 选择 目标主机、目标文件



###TODO: optimize
