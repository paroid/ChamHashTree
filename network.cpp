#include "network.h"


namespace paroid {
	void socketInit(){
		WSADATA wsd;
		if( WSAStartup( MAKEWORD( 1, 1), &wsd) != 0) {
			::std::cout<<"WSA socket Init Error!"<<::std::endl;
			return;
		}
	}
	void socketCleanUp(){
		WSACleanup();
	}

	tcpServer::tcpServer(){
		if((sockfd =  socket(AF_INET,SOCK_STREAM,0)) < 0){
			::std::cout<<"socket Init Error!"<<::std::endl;
		}
	}

	tcpServer::~tcpServer(){
		close();
	}
	void tcpServer::close(){
		if(sockfd>0)
			closesocket(sockfd);
	}
	bool tcpServer::bindListen(int port){
		struct sockaddr_in srvaddr;
		memset(&srvaddr, 0, sizeof(struct sockaddr));

		srvaddr.sin_port=htons(port);
		srvaddr.sin_family=AF_INET;
		srvaddr.sin_addr.s_addr=htonl(INADDR_ANY);
		int on=1;
		//SO_REUSEADDR  to rebind the port
		setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR|SO_LINGER, (char*)&on,sizeof(on)); 

		if(bind(sockfd,(struct sockaddr *)&srvaddr,sizeof(struct sockaddr))<0) {
			::std::cout<<"Socket Bind Error!"<<::std::endl;
			return false;
		}

		if(listen(sockfd, CONNECTQUEUELENGTH)<0) {
			::std::cout<<"Socket Listen Error!"<<::std::endl;
			return false;
		}

		return true;
	}
	int tcpServer::selectCheck(int sec){
		struct timeval timeOut;
		timeOut.tv_sec = sec;
		timeOut.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(sockfd, &fds);
		return select(sockfd + 1, &fds, NULL, NULL, &timeOut);
	}
	int tcpServer::isFDSet(){
		return FD_ISSET(sockfd,&fds);
	}
	SOCKET tcpServer::acceptConnection(){
		int size = sizeof(struct sockaddr);
		SOCKET sockfdRemote;
		if((sockfdRemote = accept(sockfd, (struct sockaddr *)&remoteAddr, &size)) < 0) {
			::std::cout<<"accept Error!"<<::std::endl;
		}
		return sockfdRemote;
	}

	tcpClient::tcpClient(){
		if((sockfd =  socket(AF_INET,SOCK_STREAM,0)) < 0){
			::std::cout<<"socket Init Error!"<<::std::endl;
		}
	}
	tcpClient::tcpClient(SOCKET sk){
		sockfd = sk;
	}
	tcpClient::~tcpClient(){
		close();
	}
	void tcpClient::close(){
		if(sockfd > 0)
			closesocket(sockfd);
	}
	int tcpClient::selectCheck(int sec){
		struct timeval timeOut;
		timeOut.tv_sec = sec;
		timeOut.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(sockfd, &fds);
		return select(sockfd + 1, &fds, NULL, NULL, &timeOut);
	}
	int tcpClient::isFDSet(){
		return FD_ISSET(sockfd,&fds);
	}
	bool tcpClient::connectTo(::std::string host,int port){
		struct sockaddr_in serverAddr;
		struct hostent *server;

		if(!(server=gethostbyname(host.c_str()))) {
			::std::cout<<"host connect  Error!"<<::std::endl;
			return false;
		}  	
		memset(&serverAddr, 0, sizeof(struct sockaddr));
		serverAddr.sin_family=AF_INET;
		serverAddr.sin_port=htons(port);
		serverAddr.sin_addr=*((struct in_addr *)server->h_addr);

		if(connect(sockfd,(struct sockaddr *)&serverAddr,sizeof(struct sockaddr))<0) {
			::std::cout<<"connect  Error!"<<::std::endl;
			return false;
		}
		return true;
	}

	char tcpClient::get(char &c){
		char res = 0;
		recv(sockfd,(char *)&res,sizeof(char),0);
		c = res;
		return res;
	}
	int tcpClient::read(char *buf,int size,int selectTime){
		if(selectTime > 0){
			int res = selectCheck(selectTime);
			if(res <= 0)
				return SELECTTIMEOUT;
		}
        return recv(sockfd,buf,size,0);
	}
	int tcpClient::write(const char *buf,int size){
		return send(sockfd,buf,size,0);
	}
}
