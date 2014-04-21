#pragma once
#ifndef ChamHashTree_H
#define ChamHashTree_H

/////////////////////////////////////////////////////////////////////
////  paroid @ 2014
/////////////////////////////////////////////////////////////////////

#include "network.h"
#include <fstream>
#include <vector>
#include <list>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <process.h>


#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")


#define ChamHashTree_DEBUG

namespace paroid {

#define HASH_LENGTH		1024
#define DIM_MSG_DGST	160
#define RSA_KEY_LENGTH	1024

#define MAX_DATASIZE	10240


#define DCAT_SETKEY		31191
#define DCAT_GETKEY		31391
#define DCAT_ADD		21321
#define DCAT_QUERY		12347
#define DCAT_OK			31
#define DCAT_ERROR		61
#define DCAT_CLOSE		79

#define SAFE 1
#define UNSAFE 0
#define TRUE 1
#define FALSE 0


	typedef enum _hashType {None, Cham, Normal, KeyNormal, ChamRand} HashType;
	typedef enum _ChamTreeRole {DataSource,Server,UserClient} RoleType;
	typedef unsigned char Byte;
	typedef unsigned long long uint64_t;
	typedef unsigned int uint32_t;

	struct chamHash_PubKey {
		chamHash_PubKey();
		~chamHash_PubKey();
		chamHash_PubKey& operator = (const chamHash_PubKey &obj);
		BIGNUM *p;
		BIGNUM *q;
		BIGNUM *g;
		BIGNUM *y;
	};

	struct chamHash_Key {
		chamHash_Key();
		~chamHash_Key();
		chamHash_Key& operator = (const chamHash_Key &obj);
		chamHash_PubKey *HK;
		BIGNUM *CK;
		BIGNUM *InvModq;
	};


	int CS_Rnd(const BIGNUM *bnN, BIGNUM *bnRnd);
	int genChamKey(const int keyLength, chamHash_Key *&cskChamKeys);
	int chamHash(const Byte *pchMsg, const uint32_t len, const BIGNUM *bnRnd, const chamHash_PubKey *HK, Byte *chamDigest);
	int chamFindCollusion(const Byte *pchMsg1, const uint32_t len1, const BIGNUM *bnRandom1, const Byte *pchMsg2, const uint32_t len2, BIGNUM *bnRandom2, const chamHash_Key *cskTrapdoor);

	inline void genRandData(Byte *data, const int len);
	inline void getRSAPubkey(RSA *pk, const RSA *key);
	int fileSHA1(const ::std::string &filename, Byte *hash);
	void showHex(const Byte *data, const int n);

	class CRC32 {
	public:
		CRC32() {
			const uint32_t Polynomial = 0xEDB88320;
			for (unsigned int i = 0; i <= 0xFF; ++i) {
				uint32_t crc = i;
				for (unsigned int j = 0; j < 8; ++j)
					crc = (crc >> 1) ^ (-int(crc & 1) & Polynomial);
				crc32Lookup[i] = crc;
			}
		}
		uint32_t check(const void* data, size_t length, uint32_t previousCrc32 = 0) {
			uint32_t crc = ~previousCrc32;
			unsigned char* current = (unsigned char*) data;
			while(length--)
				crc = (crc >> 8) ^ crc32Lookup[(crc & 0xFF) ^ *current++];
			return crc;
		}
	private:
		uint32_t crc32Lookup[256];
	};

	///////////////////////////////////
	//// HashNode
	//////////////////////////////////

	class HashNode {
	public:
		HashNode();
		virtual ~HashNode();
		virtual void updateNode() = 0;
		virtual void updateNode(const Byte *data, const int len) = 0;

		HashNode *leftChild,
			*rightChild,
			*parent,
			*brother;
		HashType type;
		Byte *hashVal;
	};

	class NormalHashNode: public HashNode {
	public:
		NormalHashNode();
		virtual ~NormalHashNode();
		void updateNode();
		void updateNode(const Byte *data, const int len);
	};

	class KeyHashNode: public NormalHashNode {
	public:
		KeyHashNode();
		virtual ~KeyHashNode();
		inline void sign(const RSA *sk);
		inline bool verify(const RSA *pk);

		Byte *signature;
		uint32_t sigLength;
	};

	class ChamHashNode: public HashNode {
	public:
		ChamHashNode(const chamHash_Key *key,bool fullConstruction = true);
		virtual ~ChamHashNode();
		void updateNode();
		void updateNode(const Byte *data, const int len);
		inline void delDummyMessage();

		BIGNUM *random;
		Byte *dummySecretMessage;
	private:
		chamHash_Key *csk;
	};

	////////////////////////////////////////////
	////  Auth
	////////////////////////////////////////////

	class AuthNode {
	public:
		AuthNode();
		virtual ~AuthNode();
		virtual void copy(const HashNode *node) = 0;
		Byte *hashVal;
		HashType type;
	};

	class NormalAuthNode: public AuthNode {
	public:
		NormalAuthNode();
		virtual ~NormalAuthNode();
		void copy(const HashNode *node);
	};
	class KeyAuthNode: public NormalAuthNode {
	public:
		KeyAuthNode();
		virtual ~KeyAuthNode();
		void copy(const HashNode *node);
		inline bool verify(const RSA *pk);

		Byte *signature;
		uint32_t sigLength;
	};
	class ChamAuthNode: public AuthNode {
	public:
		ChamAuthNode();
		virtual ~ChamAuthNode();
		void copy(const HashNode *node);
	};
	class ChamRandAuthNode: public AuthNode {
	public:
		ChamRandAuthNode();
		virtual ~ChamRandAuthNode();
		void copy(const HashNode *node);
		BIGNUM *random;
	};


	class AuthPath {
		friend class ChamServer;
	public:
		AuthPath();
		~AuthPath();
		void addNode(const HashNode *node, const HashType tp);
		void addNode(AuthNode *n);
		bool verify(const Byte *data, const int len, const RSA *pk);
		void clearNode();
		inline void setKey(const chamHash_PubKey *k);
		inline int length();
		inline void setIndex(int i);
		inline int getIndex();
	private:
		inline void computeHash(Byte *hash, const Byte *normal, const Byte *cham);
		inline void computeHash(Byte *hash, const Byte *normal, const Byte *cham, const BIGNUM *rand);
		inline void computeHash(Byte *hash, const Byte *data, const int len);
		inline void computeHash(Byte *hash, const Byte *data, const int len, const BIGNUM *rand);

		int pathLength;
		int index;
		chamHash_PubKey *key;
		::std::list<AuthNode *> path;
	};

	struct dataNode {
		dataNode(const Byte *d, const int l);
		static dataNode newDataNode(const Byte *d, const int l);
		Byte *data;
		int len;
	};


	//////////////////////////////////////////////
	////  ChamHashTree
	//////////////////////////////////////////////

	class ChamHashTree {
		friend class ChamUser;
	public:
		ChamHashTree(RoleType r);
		virtual ~ChamHashTree();
		void clear();
		bool queryData(Byte *&data, int &len, const int index, AuthPath *auth);
		bool verifyTree();
		inline const RSA* getPubKey();
		void visualize(const ::std::string &outFile);
		void copyDataList(ChamHashTree *tree);
		uint64_t getSize();
		uint64_t getCapacity();
		::std::vector<dataNode> dataList;
		RoleType role;
		CRC32 ckSumObj;
	protected:
		template <typename T>
		static void writeNode(T &stream,HashNode *node);
		template <typename T>
		static void readNode(T &stream,HashNode *node);
		HashNode *root;
		RSA *RSAPubKey;
		chamHash_PubKey *chamPubKey;
		uint64_t size;
		uint64_t capacity;
		int deepth;
		static void sendBigNum(tcpClient *client,BIGNUM *,int maxlen);
		static void recvdBigNum(tcpClient *client,BIGNUM *,int maxlen);
	private:
		void destroy(HashNode *root);
		bool verifyNode(const HashNode *rt);
		void track(::std::ofstream &out, const HashNode *rt, uint32_t *cnt, uint32_t parID = 0, uint32_t d = 0, uint32_t deep = 0);
	};


	class ChamDataSource:public ChamHashTree{
	public:
		ChamDataSource();
		ChamDataSource(const ::std::string &filename, const ::std::string &rsaKeyFilename);
		~ChamDataSource();
		int addData(const Byte *data, const int len);			
		void saveKey(const ::std::string &filename, const ::std::string &rsaKeyFilename);
		bool sendKeyToServer(); 
		bool addDataToServer(); 
		bool connectToServer(::std::string host,int port);
		bool closeConnection();
		void memToFile(::std::string filename);
		void fileToMem(::std::string filename);
		tcpClient client;
	private:
		::std::vector<HashNode *> incNode;
		chamHash_Key *csKey;
		RSA *rsaKey;
	};


	class ChamServer: public ChamHashTree{
	public:
		ChamServer();
		~ChamServer();
		void setChamPubKey(chamHash_PubKey *chamkey);
		void setRSAPubKey(RSA *rsaKey);
		bool startService(int port);
		bool stopService();
		tcpServer server;
	private:
		static unsigned int __stdcall	connectThread(void  *para);
		static unsigned int __stdcall	serveThread(void *para); //protocol A & B
		int addData(tcpClient &client);
		bool serviceStatus;
		HANDLE connectThreadHandle;
		int connectionNum;
		CRITICAL_SECTION connectionNumLock;
		CRITICAL_SECTION treeLock;
	};

	class servePara{
	public:
		servePara(tcpClient *,ChamServer *);
		tcpClient *client;
		ChamServer *tree;
	};


	class ChamUser{
		friend class ChamServer;
	public:
		ChamUser();
		ChamUser(chamHash_PubKey *c,RSA *r);
		~ChamUser();
		bool queryData(const int index,Byte *data,int &len,AuthPath *auth); //protocol B
		void getKey();
		const RSA *getRSAPubKey();
		bool connectToServer(::std::string host,int port);
		bool closeConnection();
		tcpClient user;
	private:
		template <typename T>
		static void writeAuthNode(T &stream,AuthNode *node);
		template <typename T>
		static void readAuthNode(T &stream,AuthNode *node);
		chamHash_PubKey *chamPubkey;
		RSA *RsaPubKey;
	};


	//inline functions
	int AuthPath::length() {
		return pathLength;
	}
	void AuthPath::setIndex(int i) {
		index = i;
	}
	int AuthPath::getIndex() {
		return index;
	}
	const RSA* ChamHashTree::getPubKey() {
		return RSAPubKey;
	}

	//template function
	template<typename T>
	void ChamHashTree::writeNode(T &stream, HashNode *node) {
		switch(node->type) {
		case Normal:
			stream.write("n",sizeof(char));
			break;

		case KeyNormal: {
			stream.write("k",sizeof(char));
			KeyHashNode *keyNode = static_cast<KeyHashNode *>(node);
			stream.write((const char *)&(keyNode->sigLength),sizeof(uint32_t));

			stream.write((const char *)(keyNode->signature), keyNode->sigLength);
			break;
						}
		case Cham: {
			stream.write("c",sizeof(char));
			ChamHashNode *chamNode = static_cast<ChamHashNode *>(node);
			//dummy message only for file
			if(::std::is_same<T,::std::ofstream>::value){
				int dummyLen;
				if(chamNode->dummySecretMessage != NULL) {
					dummyLen = HASH_LENGTH >> 3;
					stream.write((const char *)(&dummyLen),sizeof(uint32_t));
					stream.write((const char *)(chamNode->dummySecretMessage), HASH_LENGTH >> 3);
				}
				else {
					dummyLen = 0;
					stream.write((const char *)(&dummyLen),sizeof(uint32_t));
				}
			}
			Byte buf[HASH_LENGTH >> 3];
			int len = BN_bn2bin(chamNode->random, buf);
			if(len > (HASH_LENGTH >> 3)){
				::std::cout<<"writeNode() bn Length ERROR"<<::std::endl;
			}
			stream.write((const char *)&len,sizeof(uint32_t));
			stream.write((const char *)buf, len);
			break;
				   }
		default:
			::std::cout << "writeNode() TYPE ERROR" <<::std::endl;
		}
		stream.write((const char *)(node->hashVal), (node->type == Cham)? HASH_LENGTH >> 3 : DIM_MSG_DGST >> 3);
	}

	template <typename T>
	void ChamHashTree::readNode(T &stream, HashNode *node) {
		switch(node->type) {
		case Normal:
			break;
		case KeyNormal: 
			{
				KeyHashNode *keyNode = static_cast<KeyHashNode *>(node);
				stream.read((char *)&(keyNode->sigLength),sizeof(uint32_t));
				keyNode->signature = new Byte[keyNode->sigLength];
				stream.read((char *)keyNode->signature, keyNode->sigLength);
				break;
			}
		case Cham: 
			{
				ChamHashNode *chamNode = static_cast<ChamHashNode *>(node);
				int intBuf;
				//dummyMSG only for fstream
				if(::std::is_same<T,::std::ifstream>::value){
					stream.read((char *)&intBuf,sizeof(uint32_t));
					if(intBuf > 0) {
						if(chamNode->dummySecretMessage == NULL)
							chamNode->dummySecretMessage = new Byte[HASH_LENGTH >> 3];
						stream.read((char *)chamNode->dummySecretMessage, intBuf);
					}
				}
				stream.read((char *)&intBuf,sizeof(uint32_t));
				Byte buf[HASH_LENGTH >> 3];
				stream.read((char *)buf, intBuf);
				BN_bin2bn(buf, intBuf, chamNode->random);
				break;
			}
		default:
			::std::cout << "readNode() TYPE ERROR" <<::std::endl;
		}
		stream.read((char *)node->hashVal, (node->type == Cham)? HASH_LENGTH >> 3 : DIM_MSG_DGST >> 3);
	}

	template <typename T>
	void ChamUser::writeAuthNode(T &stream,AuthNode *node){
		switch(node->type){
		case Normal:
			stream.write("n",sizeof(char));
			stream.write((const char *)(node->hashVal),DIM_MSG_DGST >> 3);
			break;
		case KeyNormal:{
			stream.write("k",sizeof(char));
			stream.write((const char *)(node->hashVal),DIM_MSG_DGST >> 3);
			KeyAuthNode *keyNode = static_cast<KeyAuthNode *>(node);
			stream.write((const char *)&(keyNode->sigLength),sizeof(uint32_t));
			stream.write((const char *)(keyNode->signature),keyNode->sigLength);
			break;
					   }
		case Cham:
			stream.write("c",sizeof(char));
			stream.write((const char *)(node->hashVal),HASH_LENGTH >> 3);
			break;
		case ChamRand:{
			stream.write("r",sizeof(char));
			ChamRandAuthNode *crNode = static_cast<ChamRandAuthNode *>(node);
			char buf[HASH_LENGTH >> 3];
			int len = BN_bn2bin(crNode->random,(Byte *)buf);
			if(len > (HASH_LENGTH >> 3)){
				::std::cout<<"writeAuthNode Error!"<<::std::endl;
				break;
			}
			stream.write((const char *)&len,sizeof(uint32_t));
			stream.write((const char *)buf,len);
					  }
					  break;
		}
	}

	template <typename T>
	void ChamUser::readAuthNode(T &stream,AuthNode *node){
		switch(node->type){
		case Normal:
			stream.read((char *)(node->hashVal),DIM_MSG_DGST >> 3);
			break;
		case KeyNormal:{
			stream.read((char *)(node->hashVal),DIM_MSG_DGST >> 3);
			KeyAuthNode *keyNode = static_cast<KeyAuthNode *>(node);
			stream.read((char *)&(keyNode->sigLength),sizeof(uint32_t));
			keyNode->signature = new Byte[keyNode->sigLength];
			stream.read((char *)(keyNode->signature),keyNode->sigLength);
			break;
					   }
		case Cham:
			stream.read((char *)(node->hashVal),HASH_LENGTH >> 3);
			break;
		case ChamRand:{
			ChamRandAuthNode *crNode = static_cast<ChamRandAuthNode *>(node);
			int len = 0;
			stream.read((char *)&len,sizeof(uint32_t));
			if(len > (HASH_LENGTH >> 3)){
				::std::cout<<"readAuthNode Error!"<<::std::endl;
				break;
			}
			char buf[HASH_LENGTH >> 3];
			stream.read(buf,len);
			BN_bin2bn((const Byte *)buf,len,crNode->random);
			break;
					  }
		}
	}

}

#endif
