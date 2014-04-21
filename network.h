#pragma once
#ifndef NETWORK_H
#define NETWORK_H
#pragma comment(lib, "Ws2_32.lib")
#include <winsock2.h>	//winsock2 first
#include <errno.h>
#include <string>
#include <iostream>
#define CONNECTQUEUELENGTH 5
#define TIMEOUTTIME		1000
#define PACKSIZE		1200
#define SELECTTIMEOUT   -91


namespace paroid {

	void socketInit();
	void socketCleanUp();

	class tcpServer{
	public:
		tcpServer();
		~tcpServer();
		void close();
		bool bindListen(int port);
		SOCKET acceptConnection();
		int selectCheck(int sec = 1); 
		int isFDSet();
	private:
		SOCKET sockfd;
		fd_set fds;
		struct sockaddr_in remoteAddr;
	};



	class tcpClient{
	public:
		tcpClient();
		tcpClient(SOCKET);
		~tcpClient();
		void close();
		bool connectTo(::std::string host,int port);
		int selectCheck(int sec = 1); 
		char get(char &c);
		int isFDSet();
		int read(char *buf,int size,int selectTime = 0);
		int write(const char *buf,int size);
	private:
		SOCKET sockfd;
		fd_set fds;
	};

}
#endif