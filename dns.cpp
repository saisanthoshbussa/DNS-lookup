#include"stdio.h"  
#include"stdlib.h"  
#include"sys/types.h"  
#include"sys/socket.h"  
#include"string.h"  
#include"netinet/in.h"  
#include"netdb.h"
#include"arpa/inet.h"
#include<unistd.h>
#include <bits/stdc++.h>
  
using namespace std;

#define BUF_SIZE 512
#define SERVER "8.8.8.8"
#define PORT 53
#define WIDTH 16
  
//normal query
struct query {
	uint16_t length;
	string url;
	unsigned char request[BUF_SIZE];
	uint16_t reqType;
};

//initialisation explained in main fn
struct query dnsQuery = {
    .length = 12,
    .url = "",
    .request = { 0xDB, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    .reqType = 0x01
};

int createSocket() {
	//normal creation of udp socket
	int sockfd;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	//if error in creating socket
	if (sockfd < 0) {  
		printf("Error creating socket!\n");  
		exit(1);  
	}  
	return sockfd;
}

void createRequest(char * url) {
	char * word;
	int i; 
	printf("Asking DNS server %s about %s\n", SERVER, url);
	dnsQuery.url = strdup(url);
	dnsQuery.reqType = 0x01;
	//tokenising the url with respect to .
	//and append each token into dnsquery request 
 
	word = strtok(url, ".");
	while (word) 
	{
		printf("parsing hostname: \"%s\" is %ld characters\n", word, strlen(word));
		dnsQuery.request[dnsQuery.length++] = strlen(word);
		//appending whole word
		for (i = 0; i < strlen(word); i++) 
		{
			dnsQuery.request[dnsQuery.length++] = word[i];
		}
		word = strtok(NULL, ".");
	}
	// End of the host name
	dnsQuery.request[dnsQuery.length++] = 0x00; 

	// 0x0001 - Query is a Type A
	dnsQuery.request[dnsQuery.length++] = 0x00;
	dnsQuery.request[dnsQuery.length++] = dnsQuery.reqType;

	// 0x0001 - Query is class IN  (Internet address)
	dnsQuery.request[dnsQuery.length++] = 0x00; 
	dnsQuery.request[dnsQuery.length++] = 0x01;
}

void hexdump (string desc, unsigned char *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = addr;

    // Output description if given.
    if (desc!="") cout<<desc<<":"<<endl;

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
        	if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And cache a printable ASCII character for later.
		//OX20 is space OX7e is ~ outside these ranges are non printable chars here it is .
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

void lookUp(char* url,map<string,vector< string> > &cache) {

	//defining requried variables for socket creation and to store info from recv packet
	struct sockaddr_in addr;
	int socket;
	int ret, rcode, i;
	int ip = 0, dom = 0;
	int length;
	unsigned char buffer[BUF_SIZE];
	unsigned char tempBuf[3];
	uint16_t QDCOUNT; //No. of items in Question Section
	uint16_t ANCOUNT; //No. of items in Answer Section
	uint16_t NSCOUNT; //No. of items in Authority Section
	uint16_t ARCOUNT; //No. of items in Additional Section
	uint16_t QCLASS; //Specifies the class of the query
	uint16_t ATYPE; //Specifies the meaning of the data in the RDATA field
	uint16_t ACLASS; //Specifies the class of the data in the RDATA field
	uint32_t TTL; //The number of seconds the results can be cached
	uint16_t RDLENGTH; //The length of the RDATA field
	uint16_t MSGID;

	//creating udp socket
	socket = createSocket();
	memset(&addr, 0, sizeof(addr));  
	addr.sin_family = AF_INET;  
	addr.sin_addr.s_addr = inet_addr(SERVER);
	addr.sin_port = htons(PORT);
	unsigned int size = sizeof(addr);

	//visualizing the request into 16 16 groups as per the dns request format
	hexdump("sending packet", dnsQuery.request, dnsQuery.length);
	printf("dns Query len::%d\n",dnsQuery.length);
	//now send the request
	ret = sendto(socket, dnsQuery.request, dnsQuery.length, 0, 
	(struct sockaddr*)&addr, size);
	//if error in sending request
	if (ret < 0) 
	{
		printf("Error Sending Request");
		exit(1);  
	}
	
	memset(&buffer, 0, BUF_SIZE);
	//recv response from server
	ret = recvfrom(socket, buffer, BUF_SIZE, 0, (struct sockaddr*)&addr, &size);
	//if error in receiving response
	if (ret < 0) 
	{
		printf("Error Receiving Response");
		exit(1);
	} 
	//in the same way visualzing the response from server and close socket 
	//so that the resourses are released and can be used later
	hexdump("received packet", buffer, ret);
	close(socket);
	
	//extracting each field according to dns format
	rcode = (buffer[3] & 0x0F);

	QDCOUNT = (uint16_t)  buffer[4] * 0x100 + buffer[5];
	printf("entries in question section: %u\n", QDCOUNT);
	ANCOUNT = (uint16_t)  buffer[6] * 0x100 + buffer[7];
	printf("records in answer section: %u\n", ANCOUNT);
	NSCOUNT = (uint16_t)  buffer[8] * 0x100 + buffer[9];
	printf("name server resource record count: %u\n", NSCOUNT);
	ARCOUNT = (uint16_t)  buffer[10] * 0x100 + buffer[11];
	printf("additional records count: %u\n", ARCOUNT);

	printf("query type: %u\n", dnsQuery.reqType);
	QCLASS = (uint16_t) dnsQuery.request[dnsQuery.length - 2] * 0x100 + dnsQuery.request[dnsQuery.length - 1];
	printf("query class: %u\n", QCLASS);
	length = dnsQuery.length + 1;  // to skip \n

	//extract ATYPE ACLASS TTL RDLENGTH and MSGID
	ATYPE = (uint16_t) buffer[length + 1] * 0x100 + buffer[length + 2];
	printf("answer type: %u\n", ATYPE);
	ACLASS = (uint16_t) buffer[length + 3] * 0x100 + buffer[length + 4];
	printf("answer class: %u\n", ACLASS);
	TTL = (uint32_t) buffer[length + 5] * 0x1000000 + buffer[length + 6] * 0x10000 + buffer[length + 7] * 0x100 + buffer[length + 8];
	printf("seconds to cache: %u\n", TTL);
	RDLENGTH = (uint16_t) buffer[length + 9] * 0x100 + buffer[length + 10];
	printf("bytes in answer: %u\n", RDLENGTH);
	MSGID = (uint16_t) buffer[0] * 0x100 + buffer[1];
	printf("answer msg id: %u\n", MSGID); 
	 
	 
	//check whether rcode is 2/3 for which the following errors are reasons
	if (rcode == 2) 
	{
		printf("nameserver %s returned SERVFAIL:\n", SERVER);
		printf("  the name server was unable to process this query due to a\n  problem with the name server.\n");
		exit(1);
	} 
	else if (rcode == 3) 
	{
		cout<<"nameserver "<<SERVER<<" returned NXDOMAIN for "<<dnsQuery.url<<":\n";
		printf("  the domain name referenced in the query does not exist\n");
		exit(1);
	}

	//extract print and store the ip addrs
	vector<string> temp;
	string ip_str="";
	if (dnsQuery.reqType == 0x01) 
	{
		printf("DNS server's answer is: (type#=%u):", ATYPE);
		for (i = 0 ; i < ret ; i++) 
		{
			//if header matches with ip protocols
			//in dns system domain is represented using pointer as it can be very large for pointer first 2 are 
			//11's and checking that whether the it is pointer to domain name and OX01 is IN stands for internet
			//if satisfied then proceed
			if (buffer[i] == 0xC0 && buffer[i+3] == 0x01) 
			{
				ip++; 
				i += 12; //skip the header part
				//print and extract into ip_str from buffer i,i+1,i+2,i+3
				printf(" %u.%u.%u.%u\n", buffer[i], buffer[i+1], buffer[i+2], buffer[i+3]);
				ip_str+=to_string(buffer[i])+"."+to_string(buffer[i+1])+"."+to_string(buffer[i+2])+"."+to_string(buffer[i+3]);
				//as more than 1 is possible we are pushing into vector 
				temp.push_back(ip_str);
				ip_str="";
			}
			//caching it
			cache[dnsQuery.url]=temp;

		}

		//if ip=0 that means no ip addr is returned then print the same
		if (!ip) 
		{
			printf("  No IPv4 address found in the DNS response!\n");
			exit(1);
		}
	}

   
}


int main() {

	// map to store ip addrs of the previous urls to increase response time
	map<string,vector<string> > cache;
	//repetadly asking user to enter url or type exit to quit
	while(1)
	{
		cout<<"\nEnter Domain name or 'exit' to quit:\n";
		string x;
		cin>>x;
		char * url=&x[0];
		if(strcmp(url,"exit")==0)    
		{
			exit(1);
		}
		
		// if not found in cache we need to request the server
		if(cache.find(url)==cache.end())
		{
			//initializing dnsQuery packet
			dnsQuery.length = 12;
			dnsQuery.url = "";
			// first two is transaction id which is given random db,42 prefered
			dnsQuery.request[0]=0xDB;
			dnsQuery.request[1]=0x42;
			//3rd is flag OX01 means standered query
			dnsQuery.request[2]=0x01;
			//4th is also flags set to zero 
			dnsQuery.request[3]=0x00;
			//5th and 6th represent number of questions in question section which is 1 
			dnsQuery.request[4]=0x00;
			dnsQuery.request[5]=0x01;
			//7th and 8th represent number of answers in answer section which is 0
			dnsQuery.request[6]=0x00;
			dnsQuery.request[7]=0x00;
			//9th and 10th represent number of authority records ==> 0
			dnsQuery.request[8]=0x00;
			dnsQuery.request[9]=0x00;
			//11 th and 12th represent number of additional records ==> 0
			dnsQuery.request[10]=0x00;
			dnsQuery.request[11]=0x00;

			//OX01 means A type OX02 means NS etc.. since here we need ip values we have to keep A 
			dnsQuery.reqType = 0x01;

			cout<<"Not found in cache.. going to server"<<endl;
			// calls to corresponding fns
			createRequest(url);
			lookUp(url,cache);
		}
		else
		{
			//if found in cache just output that using map cache
			cout<<"Found in cache ..."<<endl;
			for(int i=0;i<cache[url].size();i++)
			{
				cout<<cache[url][i]<<endl;
			}
		 }
	}
	return 0;
}





