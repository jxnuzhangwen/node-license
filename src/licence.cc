#include <node.h>
#include <v8.h>
#include <node_buffer.h>

#include   <stdio.h> 
#include   <sys/ioctl.h> 
#include   <sys/socket.h> 
#include   <netinet/in.h> 
#include   <net/if.h> 
#include   <string.h> 
#include 	<stdlib.h>

#include <stdbool.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/rand.h>


namespace node {

using namespace v8;

char* getMac();
void hex_encode(unsigned char *md_value, int md_len, char** md_hexdigest,
                int* md_hex_len);
void base64(unsigned char *input, int length, char** buf64, int* buf64_len);
bool validate(char* buf, int len);
char *getSerialNumber();

void unbase64(unsigned char *input, int length, char** buffer, int* buffer_len)
{
  BIO *b64, *bmem;
  *buffer = (char *)malloc(length);
  memset(*buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  *buffer_len = BIO_read(bmem, *buffer, length);
  BIO_free_all(bmem);
}

Handle<Value> MachineCode(const Arguments& args) {
  HandleScope scope;
  /*return scope.Close(String::New("world"));*/
	char* serialNumber = getMac();
	Local<Value> macAddress =String::New(serialNumber, strlen(serialNumber));
	
  return scope.Close(macAddress);
}

Handle<Value> SerialNumber(const Arguments& args) {
  HandleScope scope;
  /*return scope.Close(String::New("world"));*/
	char* serialNumber = getSerialNumber();
	Local<Value> macAddress =String::New(serialNumber, strlen(serialNumber));
	
  return scope.Close(macAddress);
}

char* myMD5(char *data){
/*	printf("myMD5data: %s, %i\n", data, strlen(data));*/
	/*unsigned char *md;*/
	unsigned char md[EVP_MAX_MD_SIZE]; 
	unsigned int mdlen; 
	EVP_MD_CTX ctx; 
	const EVP_MD *type = EVP_md5();  
  OpenSSL_add_all_digests();  
	type = EVP_md5();
	EVP_DigestInit(&ctx,type);  
  EVP_DigestUpdate(&ctx,data,strlen(data)); 
  EVP_DigestFinal(&ctx,md,&mdlen);  


	/*MD5((unsigned char *)data, strlen(data),md);*/
	
		char* md_hexdigest;
		int md_hex_len;
	hex_encode(md, mdlen, &md_hexdigest, &md_hex_len);
/*printf("myMD5md_hexdigest: %s", md_hexdigest);*/
	return md_hexdigest;
}



unsigned char *getContent(unsigned char *base64, int len){
	unsigned char* ciphertext;
  int ciphertext_len;
	unbase64(base64, len, (char **)&ciphertext, &ciphertext_len);
/*	printf("ciphertext: %s", ciphertext);*/
	return ciphertext;
}

Handle<Value> RequireJSE(const Arguments& args) {
  HandleScope scope;

  ssize_t len = DecodeBytes(args[0], BINARY);
  unsigned char* buf = new unsigned char[len];
	
  (void)DecodeWrite((char *)buf, len, args[0], BINARY);
/*printf("len %i", strlen((char *)buf));*/
	/*	printf("buf: %s", (char *)buf);*/
	buf[16] = '\0';
 	bool validateResult = validate((char *)buf, len);
	
	if(validateResult){
		ssize_t len = DecodeBytes(args[1], BINARY);
  	unsigned char* buf = new unsigned char[len];
  	(void)DecodeWrite((char *)buf, len, args[1], BINARY);
		/*	printf("requirejse: %s, %i \n", buf, len);*/
  	char* ciphertext = (char *)getContent(buf, len);
		/*printf("ciphertext: %s", ciphertext);*/
		Local<Value> macAddress =String::New(ciphertext, strlen(ciphertext));
		return scope.Close(macAddress);
	}else{
		printf("licence validate failure!\n");
		return String::New("");
	}	

}

void init(Handle<Object> target) {
  NODE_SET_METHOD(target, "SerialNumber", SerialNumber);
	NODE_SET_METHOD(target, "RequireJSE",
                           RequireJSE);
	NODE_SET_METHOD(target, "MachineCode",
                           MachineCode);


}

char* getMac(){
    struct   ifreq   ifreq; 
    int   sock; 

    if((sock=socket(AF_INET,SOCK_STREAM,0)) <0) 
    { 
        perror( "socket "); 
        return 0; 
    } 
    strcpy(ifreq.ifr_name,"eth0"); 
    if(ioctl(sock,SIOCGIFHWADDR,&ifreq) <0) 
    { 
        perror( "ioctl "); 
        return 0; 
    } 
		/*return ifreq.ifr_hwaddr.sa_data;*/

/*
    printf( "%02x:%02x:%02x:%02x:%02x:%02x\n ", 
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[0], 
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[1], 
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[2], 
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[3], 
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[4], 
            (unsigned   char)ifreq.ifr_hwaddr.sa_data[5]); 
*/

		char* md_hexdigest;
		int md_hex_len;
/*
		hex_encode((unsigned char *)ifreq.ifr_hwaddr.sa_data, 6, &md_hexdigest, &md_hex_len);
*/

		base64((unsigned char *)ifreq.ifr_hwaddr.sa_data, 6, &md_hexdigest, &md_hex_len);

/*
		printf("%d", md_hex_len);
		printf("%d", strlen(md_hexdigest));
*/
		return md_hexdigest;


}

bool validate(char* buf, int len){
/*
  char* ciphertext;
  int ciphertext_len;

      unbase64((unsigned char*)buf, len, &ciphertext, &ciphertext_len);
      free(buf);
      buf = ciphertext;
      len = ciphertext_len;

		char* md_hexdigest;
		int md_hex_len;
	hex_encode((unsigned char*)buf, len, &md_hexdigest, &md_hex_len);
*/
	char* serialNumber = getSerialNumber();
/*
	printf("serialNumber: %s, %i\n",serialNumber, strlen(serialNumber));
	printf("buf: %s, %i\n",buf, strlen(buf));
	printf("validateResult: %i\n", strcmp(buf, serialNumber));
*/
		if(strcmp(buf, serialNumber) == 0){
			return true;		
		}else{
			return false;
		}

	
/*	
	printf("validate: %s\n", md_hexdigest);
	char* mac = getMac();
	printf("mac validate: %s\n", mac);
	int validateResult = strcmp(md_hexdigest, mac);
	printf("validateResult: %i\n", validateResult);
	if(validateResult == 0){
				printf("validate:true");
				return true;
	}else{
				printf("validate:false");
				return false;
	}
*/
	
}

void hex_encode(unsigned char *md_value, int md_len, char** md_hexdigest,
                int* md_hex_len) {
  *md_hex_len = (2*(md_len));
  *md_hexdigest = (char *) malloc(*md_hex_len + 1);
  for (int i = 0; i < md_len; i++) {
    sprintf((char *)(*md_hexdigest + (i*2)), "%02x",  md_value[i]);
  }
}

void base64(unsigned char *input, int length, char** buf64, int* buf64_len)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64, input, length);
  (void)BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  *buf64_len = bptr->length;
  *buf64 = (char *)malloc(*buf64_len+1);
  memcpy(*buf64, bptr->data, bptr->length);
  char* b = *buf64;
  b[bptr->length] = 0;

  BIO_free_all(b64);

}

char *getSerialNumber(){
		char *serialNumber = (char *) malloc(16 + 1); 
		serialNumber[16] = '\0';
		char* md = myMD5(getMac());
/*		printf("serialmd: %s", md);*/
		memcpy(serialNumber, (unsigned char*)md, 16);
/*		printf("serialserial: %s", serialNumber);*/

		return serialNumber;
}




NODE_MODULE(licence, init);
}
