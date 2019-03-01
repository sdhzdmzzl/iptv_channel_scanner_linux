# iptv_channel_scanner_linux
原理：  
构造igmp包，然后使用libpcap抓包，获取组播地址和端口。  
scan iptv channel in linux  
	to compile it:  
		g++ -g -o iptvscanner iptvscanner.cpp -lpcap  
usage: 
	./iptvscanner 239.3.1.1 254 
todo:  
	save m3u playlist  
