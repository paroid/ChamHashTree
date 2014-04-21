#include "ChamHashTree.h"
#include <iostream>
#include <string>
#include <queue>
#include <stack>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <openssl/rand.h>

#include <time.h>

namespace paroid {

	int fileSHA1(const ::std::string &filename, Byte *hash) {
		FILE *f;
		Byte buf[8192];
		SHA_CTX sc;
		int err;

		fopen_s(&f, filename.c_str(), "rb");
		if (f == NULL)
			return -1;
		SHA1_Init(&sc);
		while (1) {
			size_t len = fread(buf, 1, sizeof buf, f);
			if (len == 0)
				break;
			SHA1_Update(&sc, buf, len);
		}
		err = ferror(f);
		fclose(f);
		if (err)
			return -1;
		SHA1_Final(hash, &sc);
		return 0;
	}

	void genRandData(Byte *data, const int len) {
		RAND_bytes(data, len);
	}

	void getRSAPubkey(RSA *pk, const RSA *key) {
		if(!(pk->n))
			pk->n = BN_new();
		if(!(pk->e))
			pk->e = BN_new();
		if(!BN_copy(pk->n, key->n))
			::std::cout << "BN_copy() ERROR" << ::std::endl;
		if(!BN_copy(pk->e, key->e))
			::std::cout << "BN_copy() ERROR" << ::std::endl;
	}


	inline char conv(const Byte n) {
		if(n < 10)
			return n + '0';
		return n - 10 + 'A';
	}

	void showHex(const Byte *data, const int n) {
		for(int i = 0; i < n; ++i) {
			::std::cout << conv(data[i] >> 4) << conv(data[i] & 0xf);
		}
	}

	//////////////////////////////////////
	////    HashNode : base class
	//////////////////////////////////////
	HashNode::HashNode() {
		type = None;
		leftChild = rightChild = parent = brother = NULL;
		hashVal = NULL;
	}
	HashNode::~HashNode() {
		if(hashVal)
			delete[] hashVal;
	}

	/////////////////////////////////////////////////////////
	////    NormalHashNode : Normal hash node compute by SHA1
	/////////////////////////////////////////////////////////
	NormalHashNode::NormalHashNode() {
		type = Normal;
		hashVal = new Byte[DIM_MSG_DGST >> 3];
	}
	NormalHashNode::~NormalHashNode() {

	}
	void NormalHashNode::updateNode() {
		if(!leftChild || !rightChild) {
			::std::cout << "ERROR: normal hash" << ::std::endl;
			return;
		}
		Byte buf[HASH_LENGTH >> 2];
		memcpy(buf, leftChild->hashVal, DIM_MSG_DGST >> 3);
		memcpy(buf + (DIM_MSG_DGST >> 3), rightChild->hashVal, HASH_LENGTH >> 3);
		SHA1(buf, (DIM_MSG_DGST + HASH_LENGTH) >> 3, hashVal);
	}
	void NormalHashNode::updateNode(const Byte *data, const int len) {
		SHA1(data, len, hashVal);
	}

	////////////////////////////////////////////////////////
	////    KeyHashNode : key node normal hash & signature
	////////////////////////////////////////////////////////

	KeyHashNode::KeyHashNode() {
		type = KeyNormal;
		signature = NULL;
		sigLength = 0;
	}

	KeyHashNode::~KeyHashNode() {
		delete[] signature;
	}
	void KeyHashNode::sign(const RSA *sk) {
		Byte buf[RSA_KEY_LENGTH >> 2];
		if(!RSA_sign(NID_sha1, hashVal, DIM_MSG_DGST >> 3, buf, &sigLength, const_cast<RSA *>(sk)))
			::std::cout << "RSA_sign() ERROR" << ::std::endl;
		signature = new Byte[sigLength];
		memcpy(signature, buf, sigLength);
	}

	bool KeyHashNode::verify(const RSA *pk) {
		return 1 == RSA_verify(NID_sha1, hashVal, DIM_MSG_DGST >> 3, signature, sigLength, const_cast<RSA *>(pk));
	}

	////////////////////////////////////////////
	////    ChamHashNode : Chameleon hash node
	////////////////////////////////////////////
	ChamHashNode::ChamHashNode(const chamHash_Key *key, bool fullConstruction) {
		type = Cham;
		csk = const_cast<chamHash_Key *>(key);
		hashVal = new Byte[HASH_LENGTH >> 3];
		random = BN_new();
		dummySecretMessage = NULL;
		if(fullConstruction) {
			dummySecretMessage = new Byte[HASH_LENGTH >> 3];

			genRandData(dummySecretMessage, HASH_LENGTH >> 3);
			if(CS_Rnd(csk->HK->q, random))
				::std::cout << "ChamHashNode::ChamHashNode() : CS_Rnd() ERROR2" << ::std::endl;

			updateNode();
		}
	}
	ChamHashNode::~ChamHashNode() {
		BN_free(random);
		if(dummySecretMessage) {
			delete[] dummySecretMessage;
		}
	}
	void ChamHashNode::delDummyMessage() {
		delete[] dummySecretMessage;
		dummySecretMessage = NULL;
	}
	void ChamHashNode::updateNode() {
		if(leftChild && rightChild) {   //from children
			Byte buf[HASH_LENGTH >> 2];
			memcpy(buf, leftChild->hashVal, DIM_MSG_DGST >> 3);
			memcpy(buf + (DIM_MSG_DGST >> 3), rightChild->hashVal, HASH_LENGTH >> 3);

			BIGNUM *random2 = BN_new();
			if(chamFindCollusion(dummySecretMessage, HASH_LENGTH >> 3, random, buf, (DIM_MSG_DGST + HASH_LENGTH) >> 3, random2, csk))
				::std::cout << "ChamHashNode::updateNode() : chamFindCollusion() ERROR" << ::std::endl;

			if(!BN_copy(random, random2))
				::std::cout << "BN_copy() ERROR" << ::std::endl;
			BN_free(random2);

			delDummyMessage();
		}
		else if(dummySecretMessage) {   //dummy node
			if(chamHash(dummySecretMessage, HASH_LENGTH >> 3, random, csk->HK, hashVal))
				::std::cout << "ChamHashNode::updateNode() : chamHash() ERROR" << ::std::endl;
		}
	}

	void ChamHashNode::updateNode(const Byte *data, const int len) {
		BIGNUM *random2 = BN_new();
		if(chamFindCollusion(dummySecretMessage, HASH_LENGTH >> 3, random, data, len, random2, csk))
			::std::cout << "ChamHashNode::updateNode() : chamFindCollusion() ERROR2" << ::std::endl;
		if(!BN_copy(random, random2))
			::std::cout << "BN_copy() ERROR" << ::std::endl;
		BN_free(random2);

		delDummyMessage();
	}

	//////////////////////////////////////
	////    AuthNode : base class
	//////////////////////////////////////
	AuthNode::AuthNode() {
		type = None;
		hashVal = NULL;
	}

	AuthNode::~AuthNode() {
		if(hashVal)
			delete[] hashVal;
	}


	////////////////////////////////////////////
	////    NormalAuthNode : normal hash value
	////////////////////////////////////////////
	NormalAuthNode::NormalAuthNode() {
		type = Normal;
		hashVal = new Byte[DIM_MSG_DGST >> 3];
	}

	NormalAuthNode::~NormalAuthNode() {

	}

	void NormalAuthNode::copy(const HashNode *node) {
		if(node->type == Normal || node->type == KeyNormal)
			memcpy(hashVal, node->hashVal, DIM_MSG_DGST >> 3);
		else
			::std::cout << "ERROR: NormalAuthNode::copy()" << ::std::endl;
	}

	/////////////////////////////////////////////////////
	////    KeyAuthNode : normal hash value & signature
	/////////////////////////////////////////////////////
	KeyAuthNode::KeyAuthNode() {
		type = KeyNormal;
		signature = NULL;
		sigLength = 0;
	}

	KeyAuthNode::~KeyAuthNode() {
		delete[] signature;
	}

	void KeyAuthNode::copy(const HashNode *node) {
		if(node->type == KeyNormal) {
			memcpy(hashVal, node->hashVal, DIM_MSG_DGST >> 3);
			sigLength = static_cast<KeyHashNode *>(const_cast<HashNode *>(node))->sigLength;
			signature = new Byte[sigLength];
			memcpy(signature, static_cast<KeyHashNode *>(const_cast<HashNode *>(node))->signature, sigLength);
		}
		else
			::std::cout << "ERROR: KeyAuthNode::copy()" << ::std::endl;
	}

	bool KeyAuthNode::verify(const RSA *pk) {
		return 1 == RSA_verify(NID_sha1, hashVal, DIM_MSG_DGST >> 3, signature, sigLength, const_cast<RSA *>(pk));
	}

	//////////////////////////////////////////////
	////    ChamAuthNode : Chameleon hash value
	//////////////////////////////////////////////
	ChamAuthNode::ChamAuthNode() {
		type = Cham;
		hashVal = new Byte[HASH_LENGTH >> 3];
	}

	ChamAuthNode::~ChamAuthNode() {

	}
	void ChamAuthNode::copy(const HashNode *node) {
		if(node->type == Cham)
			memcpy(hashVal, node->hashVal, HASH_LENGTH >> 3);
	}


	////////////////////////////////////////////////////
	////    ChamRandAuthNode : Chameleon hash random
	////////////////////////////////////////////////////
	ChamRandAuthNode::ChamRandAuthNode() {
		type = ChamRand;
		random = BN_new();
	}

	ChamRandAuthNode::~ChamRandAuthNode() {
		BN_free(random);
	}
	void ChamRandAuthNode::copy(const HashNode *node) {
		if(node->type == Cham) {
			if(!BN_copy(random, (static_cast<ChamHashNode *>(const_cast<HashNode *>(node)))->random))
				::std::cout << "BN_copy() ERROR" << ::std::endl;
		}
		else
			::std::cout << "ChamRandAuthNode copy() ERROR" << ::std::endl;
	}


	//////////////////////////////////////////
	////    AuthPath : authentication path
	//////////////////////////////////////////
	AuthPath::AuthPath() {
		key = new chamHash_PubKey();
		pathLength = 0;
	}
	AuthPath::~AuthPath() {
		clearNode();
		delete key;
	}

	void AuthPath::setKey(const chamHash_PubKey *k) {
		*key = *k;
	}

	void AuthPath::clearNode() {
		for(::std::list<AuthNode *>::iterator it = path.begin(); it != path.end(); ++it)
			delete *it;
		path.clear();
		pathLength = 0;
		index = -1;
	}

	void AuthPath::computeHash(Byte *hash, const Byte *normal, const Byte *cham) {
		Byte buf[(HASH_LENGTH + DIM_MSG_DGST) >> 3];
		memcpy(buf, normal, DIM_MSG_DGST >> 3);
		memcpy(buf + (DIM_MSG_DGST >> 3), cham, HASH_LENGTH >> 3);
		SHA1(buf, (HASH_LENGTH + DIM_MSG_DGST) >> 3, hash);
	}
	void AuthPath::computeHash(Byte *hash, const Byte *normal, const Byte *cham, const BIGNUM *rand) {
		Byte buf[(HASH_LENGTH + DIM_MSG_DGST) >> 3];
		memcpy(buf, normal, DIM_MSG_DGST >> 3);
		memcpy(buf + (DIM_MSG_DGST >> 3), cham, HASH_LENGTH >> 3);
		if(chamHash(buf, (HASH_LENGTH + DIM_MSG_DGST) >> 3, rand, key, hash))
			::std::cout << "AuthPath::computeHash() : chamHash() ERROR" << ::std::endl;
	}

	void AuthPath::computeHash(Byte *hash, const Byte *data, const int len) {
		SHA1(data, len, hash);
	}

	void AuthPath::computeHash(Byte *hash, const Byte *data, const int len, const BIGNUM *rand) {
		if(chamHash(data, len, rand, key, hash))
			::std::cout << "AuthPath::computeHash() : chamHash() ERROR2" << ::std::endl;
	}

	void AuthPath::addNode(const HashNode *node, const HashType tp) {
		AuthNode *newNode;
		switch(tp) {
		case KeyNormal:
			newNode = new KeyAuthNode();
			break;
		case Normal:
			newNode = new NormalAuthNode();
			break;
		case Cham:
			newNode = new ChamAuthNode();
			break;
		case ChamRand:
			newNode = new ChamRandAuthNode();
			break;
		}
		newNode->copy(node);
		path.push_front(newNode);
		pathLength += (tp != ChamRand);
	}

    void AuthPath::addNode(AuthNode *node){
		path.push_back(node);
		pathLength += (node->type != ChamRand);
	}

	bool AuthPath::verify(const Byte *data, const int len, const RSA *pk) {
		//verify key signature
		if(path.back()->type != KeyNormal || !static_cast<KeyAuthNode *>(path.back())->verify(pk))
			return false;

		//verify path
		::std::list<AuthNode *>::iterator it = path.begin(), next = it;
		Byte tmpHash[2][max(HASH_LENGTH,DIM_MSG_DGST) >> 3];
		Byte flag = 0;
		++next;
		int tIndex = 0;
		int power = 1;
		if((*it)->type == ChamRand) {
			computeHash(tmpHash[flag], data, len, (static_cast<ChamRandAuthNode *>(*it))->random);
			it = next++;
			tIndex = 1;
		}
		else
			computeHash(tmpHash[flag], data, len);
		flag ^= 1;
		while(next != path.end()) {
			power <<= 1;
			if((*next)->type == ChamRand) {
				if((*it)->type == Cham)
					computeHash(tmpHash[flag], tmpHash[flag ^ 1], (*it)->hashVal, (static_cast<ChamRandAuthNode *>(*next))->random);
				else
					computeHash(tmpHash[flag], (*it)->hashVal, tmpHash[flag ^ 1], (static_cast<ChamRandAuthNode *>(*next))->random);
				++next;
				tIndex += power;
			}
			else {
				if((*it)->type == Cham)
					computeHash(tmpHash[flag], tmpHash[flag ^ 1], (*it)->hashVal);
				else
					computeHash(tmpHash[flag], (*it)->hashVal, tmpHash[flag ^ 1]);
			}

			flag ^= 1;
			it = next++;
		}
		flag ^= 1;

		return  (index == tIndex) && !memcmp(tmpHash[flag], (*it)->hashVal, DIM_MSG_DGST >> 3);
	}

	//////////////////////////////////////
	////    dataNode : data node
	//////////////////////////////////////
	dataNode::dataNode(const Byte *d, const int l) {
		data = const_cast<Byte *>(d);
		len = l;
	}

	dataNode dataNode::newDataNode(const Byte *d, const int l) {
		dataNode td(d, l);
		return td;
	}


	/////////////////////////////////////////////////////
	////    ChamHashTree : Chameleon Authentication Tree
	/////////////////////////////////////////////////////
	ChamHashTree::ChamHashTree(RoleType r){
		role = r;
		root = NULL;
		size = 0;
		capacity = 0;
		deepth = -1;
	}
	ChamHashTree::~ChamHashTree() {
		destroy(root);
		dataList.clear();
		delete chamPubKey;
		RSA_free(RSAPubKey);
		//free ex_data
		CRYPTO_cleanup_all_ex_data();
	}

	void ChamHashTree::clear() {
		destroy(root);
		dataList.clear();
		root = NULL;
		size = 0;
		capacity = 0;
		deepth = -1;
	}

	void ChamHashTree::destroy(HashNode *rt) {
		if(rt) {
			destroy(rt->leftChild);
			destroy(rt->rightChild);
			delete rt;
		}
	}


	void ChamHashTree::copyDataList(ChamHashTree *tree){
		for(::std::size_t i=0;i<tree->dataList.size();++i)
			dataList.push_back(tree->dataList[i]);
	}
	void ChamHashTree::visualize(const ::std::string &outFilename) {
		::std::ofstream gFile(outFilename);
		gFile << "digraph G {" << ::std::endl;
		gFile << "bgcolor=\"#f6f6ef\"\nratio=compress\nfontsize=12\nnodesep=0.15\nranksep=0.3\nmargin=2" << ::std::endl;
		//gFile << "margin=\"64\"" << ::std::endl;

		uint32_t cnt = 0;
		track(gFile, root, &cnt);

		gFile << "}" << ::std::endl;
		gFile.close();
	}
	void ChamHashTree::track(::std::ofstream &out, const HashNode *rt, uint32_t *cnt, uint32_t parID, uint32_t d, uint32_t deep) {
		++*cnt;
		out << *cnt << "[height=0.35,width=0.35,fixedsize=true,style=filled,color=black,fontcolor=black,fontname=consolas,label=\"";
		if(deep == deepth && !(rt->leftChild) && !rt->rightChild && size > d)
			out << d + 1;
		out << "\",fillcolor=";
		switch(rt->type) {
		case Normal:
			out << "\"#96b462\",tooltip=\"Normal HashNode\"";
			break;
		case KeyNormal:
			out << "\"#d66b39\",tooltip=\"Key HashNode\"";
			break;
		case Cham:
			out << "\"#3972d6\",tooltip=\"Cham HashNode\"";
			break;
		}
		out << "];" << ::std::endl;
		if(rt->parent)
			out << parID << " -> " << *cnt << "[dir=none];" << ::std::endl;
		uint32_t cur = *cnt;
		if(rt->leftChild)
			track(out, rt->leftChild, cnt, cur, (d << 1), deep + 1);
		if(rt->rightChild)
			track(out, rt->rightChild, cnt, cur, (d << 1) + 1, deep + 1);
	}

	bool ChamHashTree::verifyNode(const HashNode *rt) {
		if(rt->leftChild && rt->rightChild) {
			if(!verifyNode(rt->leftChild) || !verifyNode(rt->rightChild))
				return false;
			Byte buf[(HASH_LENGTH + DIM_MSG_DGST) >> 3];
			memcpy(buf, rt->leftChild->hashVal, DIM_MSG_DGST >> 3);
			memcpy(buf + (DIM_MSG_DGST >> 3), rt->rightChild->hashVal, HASH_LENGTH >> 3);
			if(rt->type == Normal || rt->type == KeyNormal) {
				SHA1(buf, (HASH_LENGTH + DIM_MSG_DGST) >> 3, buf);
				return !memcmp(buf, rt->hashVal, DIM_MSG_DGST >> 3);
			}
			else {
				if(chamHash(buf, (HASH_LENGTH + DIM_MSG_DGST) >> 3, static_cast<ChamHashNode *>(const_cast<HashNode *>(rt))->random, chamPubKey, buf))
					::std::cout << "AuthPath::computeHash() : chamHash() ERROR" << ::std::endl;
				return !memcmp(buf, rt->hashVal, HASH_LENGTH >> 3);
			}
		}
		return true;
	}

	bool ChamHashTree::verifyTree() {
		return verifyNode(root);
	}

	uint64_t ChamHashTree::getSize(){
		return size;
	}
	uint64_t ChamHashTree::getCapacity(){
		return capacity;
	}

	bool ChamHashTree::queryData(Byte *&data, int &len, const int index, AuthPath *auth) {
		if(index >= size)
			return false;

		//get data
		data = dataList[index].data;
		len = dataList[index].len;

		//auth path
		uint64_t prober = !deepth ? 0 : 1 << (deepth - 1);
		bool startFlag = false;
		HashNode *pNode = root;
		HashNode *preNode = NULL;
		auth->clearNode();
		auth->setIndex(index);
		auth->setKey(chamPubKey);

		while(prober) {
			preNode = pNode;
			pNode = (index & prober) ? pNode->rightChild : pNode = pNode->leftChild;
			if(!startFlag && (index & prober)) {    //right Node
				auth->addNode(preNode, KeyNormal);     //key root
				startFlag = true;
			}
			if(startFlag) {
				auth->addNode(pNode->brother, (pNode->brother->type == KeyNormal) ? Normal : pNode->brother->type);
				if(pNode->type == Cham)
					auth->addNode(pNode, ChamRand);
			}
			prober >>= 1;
		}
		if(!startFlag)
			auth->addNode(pNode, KeyNormal);   //key root

		return true;
	}

	void ChamHashTree::sendBigNum(tcpClient *client,BIGNUM *bn,int maxlen){
		Byte buf[max(HASH_LENGTH,RSA_KEY_LENGTH) >> 3];
		int len = BN_bn2bin(bn, buf);
		if(len > (maxlen >> 3)){
			::std::cout<<"sendKeyToServerNode() bn Length ERROR"<<::std::endl;
		}
		client->write((const char *)&len,sizeof(uint32_t));
		client->write((const char *)buf,len);
	}
	void ChamHashTree::recvdBigNum(tcpClient *client,BIGNUM *bn,int maxlen){
		Byte buf[max(HASH_LENGTH,RSA_KEY_LENGTH) >> 3];
		int len;
		if(!client->read((char *)&len,sizeof(uint32_t),TIMEOUTTIME) || len > maxlen){
			::std::cout<<"recvBigNum Error"<<::std::endl;
			return;
		}
		if(!client->read((char *)buf,len,TIMEOUTTIME)){
			::std::cout<<"recvBigNum Error"<<::std::endl;
			return;
		}
		BN_bin2bn(buf, len, bn);
	}

	/////////////////////////////////////////////////////
	// ChamDataSource
	////////////////////////////////////////////////////
	ChamDataSource::ChamDataSource() : ChamHashTree(DataSource) {
		//Cham key
		csKey = new chamHash_Key();
		if(genChamKey(HASH_LENGTH, csKey))
			::std::cout << "ChamHashTree::ChamHashTree() : genChamKey() ERROR" << ::std::endl;

		chamPubKey = csKey->HK;
		//RSA key
		rsaKey = RSA_new();
		BIGNUM *bne = BN_new();
		BN_set_word(bne, RSA_F4);
		if(!RSA_generate_key_ex(rsaKey, RSA_KEY_LENGTH, bne, NULL))
			::std::cout << "RSA_KeyGen() ERROR" << ::std::endl;;
		BN_free(bne);
		//RSA public key
		RSAPubKey = RSA_new();
		getRSAPubkey(RSAPubKey, rsaKey);
	}

	ChamDataSource::ChamDataSource(const ::std::string &filename, const ::std::string &rsaKeyFilename): ChamHashTree(DataSource) {
		csKey = new chamHash_Key();

		//Cham key
		::std::ifstream keyFile(filename);
		::std::string buf;
		int hashLen = 0;
		keyFile >> hashLen;
		if(hashLen != HASH_LENGTH) {
			::std::cout << "ChamKey Length ERROR" <<::std::endl;
			return;
		}
		keyFile >> buf;
		BN_hex2bn(&(csKey->HK->p), buf.c_str());
		keyFile >> buf;
		BN_hex2bn(&(csKey->HK->q), buf.c_str());
		keyFile >> buf;
		BN_hex2bn(&(csKey->HK->g), buf.c_str());
		keyFile >> buf;
		BN_hex2bn(&(csKey->HK->y), buf.c_str());
		keyFile >> buf;
		BN_hex2bn(&(csKey->CK), buf.c_str());
		keyFile >> buf;
		BN_hex2bn(&(csKey->InvModq), buf.c_str());
		keyFile.close();

		chamPubKey = csKey->HK;

		//RSA key
		rsaKey = RSA_new();
		FILE *file;
		fopen_s(&file, rsaKeyFilename.c_str(), "rb");
		if (!file ) {
			::std::cout << "read RSA key file ERROR" << ::std::endl;
			return;
		}
		PEM_read_RSAPrivateKey(file, &rsaKey, NULL, NULL);
		fclose(file);
		//RSA public key
		RSAPubKey = RSA_new();
		getRSAPubkey(RSAPubKey, rsaKey);
	}

	ChamDataSource::~ChamDataSource(){
		delete csKey;
		RSA_free(rsaKey);
	}


	void ChamDataSource::saveKey(const ::std::string &filename, const ::std::string &rsaKeyFilename) {
		::std::ofstream keyFile(filename);
		keyFile << HASH_LENGTH <<::std::endl;
		char *buf;
		buf = BN_bn2hex(csKey->HK->p);
		keyFile << buf << ::std::endl;
		delete[] buf;
		buf = BN_bn2hex(csKey->HK->q);
		keyFile << buf << ::std::endl;
		delete[] buf;
		buf = BN_bn2hex(csKey->HK->g);
		keyFile << buf << ::std::endl;
		delete[] buf;
		buf = BN_bn2hex(csKey->HK->y);
		keyFile << buf << ::std::endl;
		delete[] buf;
		buf = BN_bn2hex(csKey->CK);
		keyFile << buf << ::std::endl;
		delete[] buf;
		buf = BN_bn2hex(csKey->InvModq);
		keyFile << buf << ::std::endl;
		delete[] buf;
		keyFile.close();

		FILE *file;
		fopen_s(&file, rsaKeyFilename.c_str(), "wb");
		if (!file ) {
			::std::cout << "create RSA key file ERROR" << ::std::endl;
			return;
		}
		PEM_write_RSAPrivateKey(file, rsaKey, NULL, NULL, RSA_KEY_LENGTH, NULL, NULL);
		fclose(file);
	}

	void ChamDataSource::memToFile(::std::string filename) {
		Byte buf[8] = "DCAT";
		::std::ofstream file(filename, ::std::ios::binary);
		//header sign
		file.write((const char *)buf, 4);
		//hashLength
		int intmp = HASH_LENGTH;
		file.write((const char *)&intmp,sizeof(uint32_t));
		//size
		file.write((const char *)&size,sizeof(uint64_t));

		//BFS traverse
		::std::queue<HashNode *>que;
		que.push(root);
		while(!que.empty()) {
			writeNode(file, que.front());
			if(que.front()->leftChild != NULL && que.front()->rightChild != NULL) {
				que.push(que.front()->leftChild);
				que.push(que.front()->rightChild);
			}
			que.pop();
		}
		file.close();
	}

	

	void ChamDataSource::fileToMem(::std::string filename) {
		::std::ifstream file(filename, ::std::ios::binary);
		Byte buf[HASH_LENGTH >> 3];
		file.read((char *)buf, 4);
		buf[4] = 0;
		if(strcmp((const char *)buf, "DCAT")) {
			::std::cout << "ChamHashTree::fileToMem() : Header ERROR" <<::std::endl;
			return;
		}
		int intBuf;
		file.read((char *)&intBuf,sizeof(uint32_t));
		if(intBuf != HASH_LENGTH) {
			::std::cout << "ChamHashTree::fileToMem() : HASH_LENGTH ERROR" <<::std::endl;
			return;
		}
		uint64_t int64Buf;
		file.read((char *)&int64Buf,sizeof(uint64_t));
		size = int64Buf;
		capacity = 1;
		deepth = 0;
		while(capacity < size){
			capacity <<= 1;
			++deepth;
		}
		::std::queue<HashNode *>que;
		::std::stack<uint64_t> levelStack;
		//compute Level stack
		while(int64Buf != 1) {
			if(int64Buf & 1)
				++int64Buf;
			levelStack.push(int64Buf);
			int64Buf >>= 1;
		}
		char tp;
		file.get(tp);
		if(tp != 'k') {
			::std::cout << "fileToMem() root type ERROR" <<::std::endl;
		}
		int cnt = 1;
		root = new KeyHashNode();
		readNode(file, root);
		uint64_t curLevelNum;
		if(size > 1){
			que.push(root);
			que.push(NULL); //NULL separator
			curLevelNum = levelStack.top();
		}
		while(!levelStack.empty()) {
			file.get(tp);
			::std::cout << tp <<"   "<<++cnt<<::std::endl;
			if(que.front()->leftChild == NULL) {
				if(tp == 'k')
					que.front()->leftChild = new KeyHashNode();
				else if(tp == 'n')
					que.front()->leftChild = new NormalHashNode();
				else
					::std::cout << "restoreNode() leftChild type ERROR" <<::std::endl;
			}
			readNode(file, que.front()->leftChild);
			que.push(que.front()->leftChild);
			file.get(tp);
			::std::cout << tp <<"   "<<++cnt<<::std::endl;
			if(tp != 'c')
				::std::cout << "restoreNode() rightChild type ERROR" <<::std::endl;
			if(que.front()->rightChild == NULL)
				que.front()->rightChild = new ChamHashNode(csKey, false);
			readNode(file, que.front()->rightChild);
			que.push(que.front()->rightChild);
			//pointer fix
			que.front()->leftChild->parent = que.front();
			que.front()->rightChild->parent = que.front();
			que.front()->leftChild->brother = que.front()->rightChild;
			que.front()->rightChild->brother = que.front()->leftChild;
			curLevelNum -= 2;
			que.pop();
			//level end
			if(!curLevelNum) {
				while(que.front() != NULL)
					que.pop();
				que.pop();
				que.push(NULL);
				levelStack.pop();
				if(!levelStack.empty())
					curLevelNum = levelStack.top();
			}
		}
		file.close();        
	}
	

	int ChamDataSource::addData(const Byte *data, const int len) {
		incNode.clear();
		//double capacity if needed
		bool extendFlag = size == capacity;
		if(extendFlag) {
			capacity = !capacity ? 1 : capacity << 1;
			++deepth;
			HashNode *newRoot = new KeyHashNode();
			newRoot->leftChild = root;
			root = newRoot;
		}

		//track down
		uint64_t prober = !deepth ? 0 : 1 << (deepth - 1);
		HashNode *pNode = root;
		while(prober) {
			if(!pNode->leftChild)
				pNode->leftChild = new NormalHashNode();
			if(!pNode->rightChild){
				pNode->rightChild = new ChamHashNode(csKey);
				incNode.push_back(pNode->rightChild);
			}

			pNode->leftChild->parent = pNode;
			pNode->rightChild->parent = pNode;

			pNode->leftChild->brother = pNode->rightChild;
			pNode->rightChild->brother = pNode->leftChild;

			pNode = (size & prober) ? pNode->rightChild : pNode = pNode->leftChild;
			prober >>= 1;
		}

		//track up
		int updateCount = 1;
		pNode->updateNode(data, len);
		incNode.push_back(pNode);
		HashNode *preNode = pNode;
		while(pNode && (pNode->type == Normal || extendFlag)) {
			preNode = pNode;
			if(pNode = pNode->parent) {
				pNode->updateNode();
				++updateCount;
				incNode.push_back(pNode);
			}
		}
		if(preNode->type == KeyNormal)
			static_cast<KeyHashNode *>(preNode)->sign(rsaKey);

		dataList.push_back(dataNode::newDataNode(data, len));
		++size;
		return updateCount;
	}

	bool ChamDataSource::connectToServer(::std::string host,int port){
		return client.connectTo(host,port);
	}
	bool ChamDataSource::closeConnection(){
		int int32tmp = DCAT_CLOSE;
		client.write((const char *)&int32tmp,sizeof(int));
		if(!client.read((char *)&int32tmp,sizeof(int),TIMEOUTTIME) || int32tmp != DCAT_OK)
			return false;
		client.close();
		return true;
	}

	bool ChamDataSource::sendKeyToServer(){
		//header
		uint32_t int32tmp = DCAT_SETKEY;
		client.write((const char *)&int32tmp,sizeof(uint32_t));
		if(!client.read((char *)&int32tmp,sizeof(uint32_t),TIMEOUTTIME) || int32tmp != DCAT_OK){
			::std::cout<<"SendKeyToServer Error!"<<::std::endl;
			return false;
		}
		//cham pubKey
		sendBigNum(&client,chamPubKey->p,HASH_LENGTH);
		sendBigNum(&client,chamPubKey->q,HASH_LENGTH);
		sendBigNum(&client,chamPubKey->g,HASH_LENGTH);
		sendBigNum(&client,chamPubKey->y,HASH_LENGTH);

		//RSA pubkey
		sendBigNum(&client,RSAPubKey->n,RSA_KEY_LENGTH);
		sendBigNum(&client,RSAPubKey->e,RSA_KEY_LENGTH);
  
		return true;
	}
 

	bool ChamDataSource::addDataToServer(){
		// -[header] -[dataLen] -[data..] -[cksum] -[size] -[nodeNum] -[nodes..]
		uint64_t int64tmp;
		uint32_t int32tmp = DCAT_ADD;
		//header
		client.write((const char *)&int32tmp,sizeof(uint32_t));
		if(!client.read((char *)&int32tmp,sizeof(uint32_t),TIMEOUTTIME) || int32tmp != DCAT_OK)
			goto STSERROR;

		//dataLen
		uint32_t dataLen = dataList.back().len;
		client.write((const char *)&dataLen, sizeof(uint32_t));
		if(!client.read((char *)(&int32tmp),sizeof(uint32_t),TIMEOUTTIME) || int32tmp != dataLen)
			goto STSERROR;
		//data
		int packetNum = dataLen/PACKSIZE;
		for(int i = 0;i < packetNum; ++i){
			client.write((const char *)(dataList.back().data + i * PACKSIZE),PACKSIZE);
			if(!client.read((char *)&int32tmp,sizeof(uint32_t),TIMEOUTTIME) || int32tmp != i)
				goto STSERROR;
		}
		if(dataLen % PACKSIZE){
			client.write((const char *)(dataList.back().data + packetNum * PACKSIZE),dataLen % PACKSIZE);
		}
			
		//cksum
		uint32_t ckSUM = ckSumObj.check(dataList.back().data,dataList.back().len);
		client.write((const char *)&ckSUM,sizeof(uint32_t));
		if(!client.read((char *)&int32tmp,sizeof(uint32_t),TIMEOUTTIME) || int32tmp != ckSUM)
			goto STSERROR;

		//size
		client.write((char *)(&size),sizeof(uint64_t));
		if(!client.read((char *)(&int64tmp),sizeof(uint64_t),TIMEOUTTIME) || int64tmp != size)
			goto STSERROR;

		//nodes
		for(size_t i = 0;i < incNode.size(); ++i){
			writeNode(client,incNode[i]);
			if(!client.read((char *)&int32tmp,sizeof(uint32_t),TIMEOUTTIME) || int32tmp != i)
				goto STSERROR;
		}

		return true;
STSERROR:
        ::std::cout<<"SendToServer() Error!"<<::std::endl;
		return false;
	}

	///////////////////////////////////////////////////////////
	////   ChamServer
	///////////////////////////////////////////////////////////

	ChamServer::ChamServer():ChamHashTree(Server){
		chamPubKey = new chamHash_PubKey();
		RSAPubKey = RSA_new();
		RSAPubKey->n = BN_new();
		RSAPubKey->e = BN_new();
		InitializeCriticalSection(&connectionNumLock);
		InitializeCriticalSection(&treeLock);
	}
	ChamServer::~ChamServer(){
		DeleteCriticalSection(&connectionNumLock);
		DeleteCriticalSection(&treeLock);
	}

	void ChamServer::setChamPubKey(chamHash_PubKey *chamkey){
		*chamPubKey = *chamkey;
	}

	void ChamServer::setRSAPubKey(RSA *rsaKey){
		getRSAPubkey(RSAPubKey,rsaKey);
	}

	bool ChamServer::startService(int port){
		server.bindListen(port);
		serviceStatus = true;
		connectionNum = 0;
		unsigned dwThreadID;
		servePara *para = new servePara(NULL,this);
		connectThreadHandle = (HANDLE)_beginthreadex(NULL, 0, &connectThread, (LPVOID)para, 0, &dwThreadID);
		if(!connectThreadHandle){
			::std::cout<<"connect Thread Error!"<<::std::endl;
			return false;
		}
		return true;
	}
	bool ChamServer::stopService(){
		serviceStatus = false;
		while(1){
			DWORD res = WaitForSingleObject(connectThreadHandle, 50);
			if(res == WAIT_OBJECT_0)
				break;
			else{
    			//do something to terminate threads
			}
		}
		while(connectionNum){
			Sleep(50);
		}
		return true;
	}

	unsigned int __stdcall	ChamServer::connectThread(void *para){
		servePara *m = (servePara *)para;
		while(m->tree->serviceStatus){
			tcpClient *serveClient = NULL;
			if(m->tree->server.selectCheck() > 0){
				serveClient = new tcpClient(m->tree->server.acceptConnection());
			}else{
				continue;
			}
			HANDLE hThread = NULL;
			unsigned dwThreadID;
			servePara *para = new servePara(serveClient,m->tree);
			hThread = (HANDLE)_beginthreadex(NULL, 0, &serveThread, (LPVOID)para, 0, &dwThreadID);
			CloseHandle(hThread);
			EnterCriticalSection(&m->tree->connectionNumLock);
			++m->tree->connectionNum;
			LeaveCriticalSection(&m->tree->connectionNumLock);
			::std::cout<<"new client connected!"<<::std::endl;
		}
		delete para;
		//_endthreadex(0);
		return 0;
	}

	unsigned int __stdcall ChamServer::serveThread(void *para){
		servePara *m = (servePara *)para;
		uint64_t int64tmp;
		uint32_t int32tmp;
		while(m->tree->serviceStatus){
			//protocol:    ADD & QUERY
RESET_ERROR:
			LeaveCriticalSection(&m->tree->treeLock);
			::std::cout<<"----"<<::std::endl;
			int state = m->client->read((char *)&int32tmp,sizeof(uint32_t),3);
			if(state == SELECTTIMEOUT) //timeout
				continue;
			if(!state || state == SOCKET_ERROR) //close connection				
				break;
			switch(int32tmp){
			case DCAT_SETKEY:{
				// +[header] +[chamKey] +[RSAKey]
				int32tmp = DCAT_OK;
				m->client->write((const char *)&int32tmp,sizeof(uint32_t));
				//cham pubKey
				recvdBigNum(m->client,m->tree->chamPubKey->p,HASH_LENGTH);
				recvdBigNum(m->client,m->tree->chamPubKey->q,HASH_LENGTH);
				recvdBigNum(m->client,m->tree->chamPubKey->g,HASH_LENGTH);
				recvdBigNum(m->client,m->tree->chamPubKey->y,HASH_LENGTH);

				//RSA pubkey
				recvdBigNum(m->client,m->tree->RSAPubKey->n,RSA_KEY_LENGTH);
				recvdBigNum(m->client,m->tree->RSAPubKey->e,RSA_KEY_LENGTH);
				::std::cout<<"KeySet() done!"<<::std::endl;
				break;
						  }
			case DCAT_GETKEY:{
				// +[header] -[chamKey] -[RSAKey]
				int32tmp = DCAT_OK;
				m->client->write((const char *)&int32tmp,sizeof(uint32_t));
				//cham pubkey
				sendBigNum(m->client,m->tree->chamPubKey->p,HASH_LENGTH);
				sendBigNum(m->client,m->tree->chamPubKey->q,HASH_LENGTH);
				sendBigNum(m->client,m->tree->chamPubKey->g,HASH_LENGTH);
				sendBigNum(m->client,m->tree->chamPubKey->y,HASH_LENGTH);
				//RSA pubkey
				sendBigNum(m->client,m->tree->RSAPubKey->n,RSA_KEY_LENGTH);
				sendBigNum(m->client,m->tree->RSAPubKey->e,RSA_KEY_LENGTH);

				::std::cout<<"KeySent() done!"<<::std::endl;
				break;
							 }
			case DCAT_CLOSE:{
				int int32tmp = DCAT_OK;
				m->client->write((const char *)&int32tmp,sizeof(int));
				goto CONNECTION_END;
				break;
							}
			case DCAT_ADD:{
        		// +[header] +[dataLen] +[data..] +[cksum] +[size] +[nodeNum] +[nodes..]
				EnterCriticalSection(&m->tree->treeLock);
				int32tmp = DCAT_OK;
				m->client->write((const char *)&int32tmp,sizeof(uint32_t));
				//dataLen
				uint32_t dataLen;
				if(!m->client->read((char *)&dataLen,sizeof(uint32_t),TIMEOUTTIME))
					goto RESET_ERROR;
				m->client->write((const char *)&dataLen,sizeof(uint32_t));

				//data
				Byte *data = new Byte[dataLen];
				int packetNum = dataLen/PACKSIZE;
				for(int i = 0;i < packetNum; ++i){
					if(!m->client->read((char *)(data + i * PACKSIZE),PACKSIZE,TIMEOUTTIME))
						goto RESET_ERROR;
					m->client->write((const char *)&i,sizeof(int));
				}
				if(dataLen % PACKSIZE){
					if(!m->client->read((char *)(data + packetNum * PACKSIZE),dataLen % PACKSIZE,TIMEOUTTIME))
						goto RESET_ERROR;
				}

				//cksum
				uint32_t ckSum;
				if(!m->client->read((char *)&ckSum,sizeof(uint32_t),TIMEOUTTIME))
					goto RESET_ERROR;
				int32tmp = m->tree->ckSumObj.check(data, dataLen);
				m->client->write((const char *)&int32tmp,sizeof(uint32_t));
				if(int32tmp != ckSum)
					goto RESET_ERROR;

				//size
				if(!m->client->read((char *)&int64tmp,sizeof(uint64_t),TIMEOUTTIME))
					goto RESET_ERROR;
				++m->tree->size;
				m->client->write((const char *)&m->tree->size,sizeof(uint64_t));
				if(m->tree->size != int64tmp)
					goto RESET_ERROR;
				--m->tree->size;
				m->tree->dataList.push_back(dataNode::newDataNode(data,dataLen));
				//nodes
				m->tree->addData(*(m->client));
    			LeaveCriticalSection(&m->tree->treeLock);
				::std::cout<<"addDataServer() done!"<<::std::endl;
				break;
						  }
			case DCAT_QUERY:{
        		// +[header] +[index] -[dataLen] -[data..] -[Auth] 
				EnterCriticalSection(&m->tree->treeLock);
				int32tmp = DCAT_OK;
				m->client->write((const char *)&int32tmp,sizeof(uint32_t));
				int index;
				m->client->read((char *)&index,sizeof(int));
				AuthPath *auth = new AuthPath();
				Byte *data;
				int dataLen;
				if(!m->tree->queryData(data,dataLen,index,auth)){
					int32tmp = DCAT_ERROR;
					m->client->write((const char *)&int32tmp,sizeof(uint32_t));
					goto RESET_ERROR;
				}
				int32tmp = DCAT_OK;
				m->client->write((const char *)&int32tmp,sizeof(uint32_t));
				m->client->write((const char *)&dataLen,sizeof(int));
				int packetNum = dataLen / PACKSIZE;
				for(int i=0;i<packetNum;++i){
					m->client->write((const char *)(data + i * PACKSIZE),PACKSIZE);
					if(!m->client->read((char *)&int32tmp,sizeof(int),TIMEOUTTIME) || int32tmp != DCAT_OK)
						goto RESET_ERROR;
				}
				if(dataLen % PACKSIZE){
					m->client->write((const char *)(data + packetNum * PACKSIZE),dataLen % PACKSIZE);
				}
				showHex(data,dataLen);
				::std::cout<<::std::endl;
				//auth
				int32tmp = auth->path.size();
				m->client->write((char *)&int32tmp,sizeof(int));
				for(::std::list<AuthNode *>::iterator it = auth->path.begin();it != auth->path.end();++it){
					ChamUser::writeAuthNode(*(m->client),*it);
				}
				LeaveCriticalSection(&m->tree->treeLock);
				::std::cout<<"queryProcesse() done!"<<::std::endl;
				break;
							}
			}
		}
CONNECTION_END:
		EnterCriticalSection(&m->tree->connectionNumLock);
		--m->tree->connectionNum;
		LeaveCriticalSection(&m->tree->connectionNumLock);
		::std::cout<<"connection closed!"<<::std::endl;
		delete para;
		_endthreadex(0);
		return 0;
	}
	int ChamServer::addData(tcpClient &client){
		//double capacity if needed
		char tp;
		int msgCnt = 0;
		bool extendFlag = size == capacity;
		if(extendFlag) {
			capacity = !capacity ? 1 : capacity << 1;
			++deepth;
			HashNode *newRoot = new KeyHashNode();
			newRoot->leftChild = root;
			root = newRoot;
		}
		
		//track down
		uint64_t prober = !deepth ? 0 : 1 << (deepth - 1);
		HashNode *pNode = root;
		while(prober) {
			if(!pNode->leftChild)
				pNode->leftChild = new NormalHashNode();
			if(!pNode->rightChild){
				pNode->rightChild = new ChamHashNode(NULL,false);
        		client.get(tp);
				readNode(client,pNode->rightChild);
				client.write((const char *)&msgCnt,sizeof(int));
				++msgCnt;
			}

			pNode->leftChild->parent = pNode;
			pNode->rightChild->parent = pNode;

			pNode->leftChild->brother = pNode->rightChild;
			pNode->rightChild->brother = pNode->leftChild;

			pNode = (size & prober) ? pNode->rightChild : pNode = pNode->leftChild;
			prober >>= 1;
		}

		//track up
		int updateCount = 1;
		client.get(tp);
		readNode(client,pNode);
		client.write((const char *)&msgCnt,sizeof(int));
		++msgCnt;
		HashNode *preNode = pNode;
		while(pNode && (pNode->type == Normal || extendFlag)) {
			preNode = pNode;
			if(pNode = pNode->parent) {
				++updateCount;
				client.get(tp);
				readNode(client,pNode);
				client.write((const char *)&msgCnt,sizeof(int));
				++msgCnt;
			}
		}
		++size;
		return updateCount;
	}



	servePara::servePara(tcpClient *c,ChamServer *t){
		client = c;
		tree = t;
	}

	///////////////////////////////////////
	/////  ChamUser
	///////////////////////////////////////

	ChamUser::ChamUser(){
		chamPubkey = new chamHash_PubKey();
		RsaPubKey = RSA_new();
		RsaPubKey->n = BN_new();
		RsaPubKey->e = BN_new();
	}

	ChamUser::ChamUser(chamHash_PubKey *c,RSA *r){
		chamPubkey = new chamHash_PubKey();
		*chamPubkey = *c;
		getRSAPubkey(RsaPubKey,r);
	}

	ChamUser::~ChamUser(){
		delete chamPubkey;
		RSA_free(RsaPubKey);
	}
	bool ChamUser::connectToServer(::std::string host,int port){
		return user.connectTo(host,port);
	}
	bool ChamUser::closeConnection(){
		int int32tmp = DCAT_CLOSE;
		user.write((const char *)&int32tmp,sizeof(int));
		if(!user.read((char *)&int32tmp,sizeof(int),TIMEOUTTIME) || int32tmp != DCAT_OK)
			return false;
		user.close();
		return true;
	}
	bool ChamUser::queryData(const int index,Byte *data,int &len,AuthPath *auth){
		// -[header] -[index] +[dataLen] +[data..] +[authNum] +[Auth] 
		auth->clearNode();
		auth->setIndex(index);
		auth->setKey(chamPubkey);
		//header
		int int32tmp = DCAT_QUERY;
		user.write((const char *)&int32tmp,sizeof(int));
		if(!user.read((char *)&int32tmp,sizeof(int),TIMEOUTTIME) || int32tmp != DCAT_OK){
			::std::cout<<"queryData Error!"<<::std::endl;
			return false;
		}
		user.write((const char *)&index,sizeof(int));
		if(!user.read((char *)&int32tmp,sizeof(int),TIMEOUTTIME) || int32tmp != DCAT_OK){
			::std::cout<<"queryData Error!"<<::std::endl;
			return false;
		}
		user.read((char *)&int32tmp,sizeof(int));		
		len = int32tmp;
		int32tmp = DCAT_OK;
		int packetNum = len / PACKSIZE;
		for(int i=0;i<packetNum;++i){
			if(!user.read((char *)(data + i * PACKSIZE),PACKSIZE,TIMEOUTTIME))
				return false;
			user.write((const char *)&int32tmp,sizeof(int));
		}
		if(len % PACKSIZE){
			user.read((char *)(data + packetNum * PACKSIZE),len % PACKSIZE);
		}

		//auth
		user.read((char *)&int32tmp,sizeof(int));
		for(int i=0;i<int32tmp;++i){
			char tp;
			user.get(tp);
			AuthNode *node = NULL;
			switch(tp){
			case 'n':
				node = new NormalAuthNode();
				break;
			case 'k':
				node = new KeyAuthNode();
				break;
			case 'c':
				node = new ChamAuthNode();
				break;
			case 'r':
				node = new ChamRandAuthNode();
				break;
			}
            readAuthNode(user,node);
			auth->addNode(node);
		}
		return true;
	}
	void ChamUser::getKey(){
		uint32_t int32tmp =DCAT_GETKEY;
		user.write((const char *)&int32tmp,sizeof(uint32_t));
		if(!user.read((char *)&int32tmp,sizeof(uint32_t),TIMEOUTTIME) || int32tmp != DCAT_OK)
			::std::cout<<"getKey Error!"<<::std::endl;
		//cham pubkey
		ChamHashTree::recvdBigNum(&user,chamPubkey->p,HASH_LENGTH);
		ChamHashTree::recvdBigNum(&user,chamPubkey->q,HASH_LENGTH);
		ChamHashTree::recvdBigNum(&user,chamPubkey->g,HASH_LENGTH);
		ChamHashTree::recvdBigNum(&user,chamPubkey->y,HASH_LENGTH);
		//RSA pubkey
		ChamHashTree::recvdBigNum(&user,RsaPubKey->n,RSA_KEY_LENGTH);
		ChamHashTree::recvdBigNum(&user,RsaPubKey->e,RSA_KEY_LENGTH);
	}

	const RSA* ChamUser::getRSAPubKey(){
		return RsaPubKey;
	}

	///////////////////////////////////////////
	////    chamHash_PubKey : Chameleon public key
	///////////////////////////////////////////
	chamHash_PubKey::chamHash_PubKey() {
		p = BN_new();
		q = BN_new();
		g = BN_new();
		y = BN_new();
	}

	chamHash_PubKey::~chamHash_PubKey() {
		BN_free(p);
		BN_free(q);
		BN_free(g);
		BN_free(y);
	}

	chamHash_PubKey& chamHash_PubKey::operator = (const chamHash_PubKey &obj) {
		if(!BN_copy(p, obj.p))
			::std::cout << "BN_copy() ERROR" << ::std::endl;
		if(!BN_copy(q, obj.q))
			::std::cout << "BN_copy() ERROR" << ::std::endl;
		if(!BN_copy(g, obj.g))
			::std::cout << "BN_copy() ERROR" << ::std::endl;
		if(!BN_copy(y, obj.y))
			::std::cout << "BN_copy() ERROR" << ::std::endl;
		if(!p || !q || !g || !y)
			::std::cout << "chamHash_PubKey::operator=() : BN_copy() ERROR" << ::std::endl;
		return *this;
	}


	////////////////////////////////////////////////////////
	////    chamHash_Key : Chameleon private key & public key
	////////////////////////////////////////////////////////
	chamHash_Key::chamHash_Key() {
		HK = new chamHash_PubKey();
		CK = BN_new();
		InvModq = BN_new();
	}

	chamHash_Key::~chamHash_Key() {
		delete HK;
		BN_clear_free(CK);
		BN_clear_free(InvModq);
	}

	chamHash_Key& chamHash_Key::operator = (const chamHash_Key &obj) {
		*HK = *(obj.HK);
		if(!BN_copy(CK, obj.CK))
			::std::cout << "BN_copy() ERROR";
		if(!BN_copy(InvModq, obj.InvModq))
			::std::cout << "BN_copy() ERROR";
		return *this;
	}

	int CS_Rnd(const BIGNUM *bnN, BIGNUM *bnRnd) {
		do {
			if (BN_rand_range(bnRnd, bnN) == 0) {
				return 1;
			}
		}
		while ((BN_cmp(bnRnd, bnN) != (-1)) || BN_is_zero(bnRnd));

		return 0;
	}

	int genChamKey(const int keyLength, chamHash_Key *&cskChamKeys) {
		BN_CTX *bnCtx = BN_CTX_new();

		//prime p
		if (!BN_generate_prime(cskChamKeys->HK->p, keyLength, SAFE, NULL, NULL, NULL, NULL))
			return 1;

		//q = (p-1)/2  also a prime
		if(!BN_copy(cskChamKeys->HK->q, cskChamKeys->HK->p))
			return 2;
		/*if (!BN_sub_word(cskChamKeys->HK->q, 1))
		return 3;*/
		if (!BN_rshift1(cskChamKeys->HK->q, cskChamKeys->HK->q))
			return 4;

		//random g
		if (CS_Rnd(cskChamKeys->HK->p, cskChamKeys->HK->g))
			return 5;
		//g = g^2 mod p
		if (!BN_mod_sqr(cskChamKeys->HK->g, cskChamKeys->HK->g, cskChamKeys->HK->p, bnCtx))
			return 6;

		//random CK as private key
		if (CS_Rnd(cskChamKeys->HK->q, cskChamKeys->CK))
			return 7;

		//y = g^CK mod p
		if (!BN_mod_exp(cskChamKeys->HK->y, cskChamKeys->HK->g, cskChamKeys->CK, cskChamKeys->HK->p, bnCtx))
			return 8;

		//InvModq = CK^-1 mod q
		if (!BN_mod_inverse(cskChamKeys->InvModq, cskChamKeys->CK, cskChamKeys->HK->q, bnCtx))
			return 9;

		BN_CTX_free(bnCtx);

		return 0;
	}


	int chamHash(const Byte *pchMsg, const uint32_t len, const BIGNUM *bnRnd, const chamHash_PubKey *HK, Byte *chamDigest) {

		BIGNUM *bnGM = BN_new();
		BIGNUM *bnMsgDgst = BN_new();
		BIGNUM *bnYR = BN_new();
		BN_CTX *bnCtx = BN_CTX_new();

		Byte* pchMsgDgst = new Byte[DIM_MSG_DGST >> 3];
		SHA1(pchMsg, len, pchMsgDgst);

		BN_bin2bn(pchMsgDgst, (DIM_MSG_DGST >> 3), bnMsgDgst);
		delete[] pchMsgDgst;
		if (!bnMsgDgst)
			return 1;

		//bnGM = g^bnMsgDgst mod p
		if (!BN_mod_exp(bnGM, HK->g, bnMsgDgst, HK->p, bnCtx))
			return 2;

		//bnYR = y^bnRnd mod p
		if (!BN_mod_exp(bnYR, HK->y, bnRnd, HK->p, bnCtx))
			return 3;

		BIGNUM *bnChamDigest = BN_new();
		//bnChamDigest = bnGM*bnYR mod p
		//             = g^(bnMsgDgst + CK*bnRnd) mod p
		if (!BN_mod_mul(bnChamDigest, bnGM, bnYR, HK->p, bnCtx))
			return 4;
		int hashLen = BN_bn2bin(bnChamDigest, chamDigest);
		if(hashLen != HASH_LENGTH >> 3) {
			if(hashLen < HASH_LENGTH >> 3)
				memset(chamDigest + hashLen, 0, (HASH_LENGTH >> 3) - hashLen);
			else
				::std::cout << "CHAM HASH_LENGTH ERROR" << ::std::endl;
		}

		BN_free(bnChamDigest);
		BN_free(bnGM);
		BN_free(bnMsgDgst);
		BN_free(bnYR);
		BN_CTX_free(bnCtx);

		return 0;
	}

	int chamFindCollusion(const Byte *pchMsg1, const uint32_t len1, const BIGNUM *bnRandom1, const Byte *pchMsg2, const uint32_t len2, BIGNUM *bnRandom2, const chamHash_Key *cskTrapdoor) {

		BIGNUM *bnMsgDgst1 = BN_new();
		BIGNUM *bnMsgDgst2 = BN_new();

		Byte* pchMsgDgst1 = new Byte[DIM_MSG_DGST >> 3];
		Byte* pchMsgDgst2 = new Byte[DIM_MSG_DGST >> 3];

		SHA1(pchMsg1, len1, pchMsgDgst1);
		SHA1(pchMsg2, len2, pchMsgDgst2);

		BN_bin2bn(pchMsgDgst1, DIM_MSG_DGST >> 3, bnMsgDgst1);
		BN_bin2bn(pchMsgDgst2, DIM_MSG_DGST >> 3, bnMsgDgst2);

		delete[] pchMsgDgst1;
		delete[] pchMsgDgst2;

		if (!bnMsgDgst2 || !bnMsgDgst2)
			return 1;

		BIGNUM *bnMDiff = BN_new();
		BIGNUM *bnMDiffDivAlpha = BN_new();
		BN_CTX *bnCtx = BN_CTX_new();

		//bnMDiff = bnMsgDgst1 - bnMsgDgst2
		if (!BN_sub(bnMDiff, bnMsgDgst1, bnMsgDgst2))
			return 2;
		BN_free(bnMsgDgst1);
		BN_free(bnMsgDgst2);

		//bnMDiffDivAlpha = bnMDiff * bnAlphaInverse
		if (!BN_mul(bnMDiffDivAlpha, bnMDiff, cskTrapdoor->InvModq, bnCtx))
			return 3;

		//bnRandom2 = bnMDiffDivAlpha + bnRandom1 mod q
		//          = (bnMsgDgst1 - bnMsgDgst2)CK^-1  + bnRandom1
		if (!BN_mod_add(bnRandom2, bnMDiffDivAlpha, bnRandom1, cskTrapdoor->HK->q, bnCtx))
			return 4;

		BN_free(bnMDiff);
		BN_free(bnMDiffDivAlpha);
		BN_CTX_free(bnCtx);

		return 0;
	}

}
