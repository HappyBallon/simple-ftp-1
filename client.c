#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "vars.h"
#include "utils.h"

enum USER_CMD {
    USER_INVALID = -1,
    USER_LS = 0,
    USER_PWD,
    USER_CD,
    USER_CDUP,
    USER_RENAME,
    USER_PUT,
    USER_GET,
    USER_USER,
    USER_PASS,
    USER_TYPE,
    USER_BYE,
    USER_MKD,
    USER_DELE,
    USER_RNFR,
    USER_RNTO,
    USER_RMD,
    USER_LCD,
    USER_LLS,
    USER_LPWD,
    USER_HELP,
    USER_COUNT
};

struct ftp_cmd USER_CMD_LIST[USER_COUNT] = {
    {"LS", USER_LS},
    {"PWD", USER_PWD},
    {"CD", USER_CD},
    {"CDUP", USER_CDUP},
    {"RENAME", USER_RENAME},
    {"PUT", USER_PUT},
    {"GET", USER_GET},
    {"USER", USER_USER},
    {"PASS", USER_PASS},
    {"TYPE", USER_TYPE},
    {"BYE", USER_BYE},
    {"MKD", USER_MKD},
    {"DELE", USER_DELE},
    {"RNFR", USER_RNFR},
    {"RNTO", USER_RNTO},
    {"RMD", USER_RMD},
    {"LCD", USER_LCD},
    {"LLS", USER_LLS},
    {"LPWD", USER_LPWD},
    {"HELP", USER_HELP}
};

enum USER_CMD parse_input_cmd(char* buf, int len) {
    int i, j;
    for (i=0; i<sizeof(USER_CMD_LIST)/sizeof(USER_CMD_LIST[0]); i++) {
        for(j=0; USER_CMD_LIST[i].name[j] && j < len; j++) {
            if (USER_CMD_LIST[i].name[j] != buf[j] & 0x1f && USER_CMD_LIST[i].name[j] != buf[j]- 32) 
                break;
        }
        if (USER_CMD_LIST[i].name[j] == '\0' && (buf[j]==' ' || buf[j]==0))
            return USER_CMD_LIST[i].cmd;
    }
    return USER_INVALID;
}

enum CLIENT_STATE {
    ST_NONE,
    ST_PASVLIST,
    ST_PASVLIST2,
    ST_PASVGET,
    ST_PASVGET2,
    ST_PASVPUT,
    ST_PASVPUT2
};

int running = 1;

void ouch() {
    running = 0;
}

int main(int argc, char *argv[]) {
    int server_port = 2121;

    if (argc < 2) {
        printf("usage: %s <addr> [2121]\n", argv[0]);
        exit(0);
    }
    if (argc == 3) {
        server_port = atoi(argv[2]);
    }
    int client = new_client(ntohl(inet_addr(argv[1])), server_port);
    if (client < 0) {
        err(1, "can not connect to %s %d", argv[1], server_port);
        err(1, "exit ...");
        exit(1);
    }
    int i, n, loginchk=1;
    char buf[BUF_SIZE+1];
    char tmpbuf[BUF_SIZE+1];
    char cmdbuf[BUF_SIZE+1];
    int data_client = -1;
    struct sockaddr_in data_client_addr;
    uint32_t addr;
    uint16_t port;
    char path[BUF_SIZE];
    int code = -1;
    enum CLIENT_STATE state = ST_NONE;
    char filename[BUF_SIZE], line[BUF_SIZE];
	
    while ((n=recv(client, buf, sizeof(buf), MSG_PEEK)) > 0) {
        if (!running) break;
        for (i=0; i<n; i++) {
            if (buf[i] == '\n') break;
        }
        if (buf[i] != '\n') {
            err(1, "no line break found");
            break;
        }
        n = recv(client, buf, i+1, 0);
        buf[n] = 0;
        printf("%s", buf);
        fflush(stdout);
        parse_number(buf, &code);
        if (code < RPL_ERR_UNKWNCMD && state != ST_NONE) {
            switch(state) {
                case ST_PASVLIST:
                case ST_PASVGET:
                case ST_PASVPUT:
                    if (code == RPL_PASVOK) {
                        strcpy(tmpbuf, buf);
                        tmpbuf[0] = tmpbuf[1] = tmpbuf[2] = tmpbuf[3] = ' ';
                        parse_addr_port(tmpbuf, &addr, &port);
                        switch(state) {
                            case ST_PASVLIST:
                                send_str(client, "LIST\r\n");
                                break;
                            case ST_PASVGET:
                                send_str(client, "RETR %s\r\n", filename);
                                break;
                            case ST_PASVPUT:
                                send_str(client, "STOR %s\r\n", filename);
                                break;
                        }
                        data_client = new_client(addr, port);
                        state++;
                    } else {
                        state = ST_NONE;
                    }
                    break;
                case ST_PASVLIST2:
                case ST_PASVGET2:
                case ST_PASVPUT2:
                    if (data_client < 0) {
                        err(1, "data client not created");
                    } else {
                        if (state == ST_PASVLIST2) {
                            recv_file(data_client, stdout);
                        } else if (state == ST_PASVGET2) {

                            recv_path(data_client, filename, 0);
			    char recv_hash[100]={0};
			    recv(client, buf ,sizeof(buf), MSG_PEEK);
				sleep(1);
			    recv(client, recv_hash ,sizeof(recv_hash), MSG_PEEK);
			    char hash[100] = {0};
			    int i;
         		    for(i=0;i<50;i++){   //dump buf clear
				recv_hash[i]=recv_hash[i+25];
		            }
			    FILE *f =fopen(filename,"rb"); //check checksum
			    fseek(f ,0 ,SEEK_END );
			    int size = ftell(f);
			    char* data = NULL;
			    data = (char*)calloc((size+1), sizeof(char));
			    fread( data , 1 , size , f );
			    integrity_check(data, hash);
			    fclose(f);
			    //printf("recv_hash : %s\nhash : %s\n",recv_hash,hash);
			    if( strncmp(hash,recv_hash,32)==0 ){
				printf("File is not tampered!!\n");
				strcpy(recv_hash,buf);
			    }
			    else{
				char rm_file[100]="rm ";
				strcat(rm_file,filename);
				printf("File is tampered!!\n"); 
				system(rm_file); 
			    }			    

                        } else if (state == ST_PASVPUT2) {
                            FILE *f = fopen(filename, "rb");
                            if (f) {
                                send_file(data_client, f);
                                fclose(f);
                            } else {
                                err(1, "err open file %s", filename);
                            }
                        }
                        info(1, "closing data socket ... %d", close(data_client));
                        data_client = -1;
                        state = ST_NONE;
                    }
                    break;
                default:
                    state = ST_NONE;
                    break;
            }
            if (code < RPL_ERR_UNKWNCMD)
                continue;
        }
        if (code >= RPL_ERR_UNKWNCMD) state = ST_NONE;
	
	
	if(loginchk){			//처음에는 loginchk는 1
	char ID[20];			//입력받은 id를 저장할 버퍼
	char PASS[20];			//입력받은 password를 저장할 버퍼
	send_str(client, "ID\r\n");	//server에 ID 명령어를 전송
	printf("Enter ID : ");		
	gets(ID);			//사용자에게 id 입력 요청
	ID[strlen(ID)] = 0;		//ID 버퍼 맨 끝에 널값 추가
	send_str(client, ID);		//server에 id 전송
	printf("Enter PASSWORD : ");
	gets(PASS);			//사용자에게 password 입력 요청
	PASS[strlen(PASS)] = 0;		//PASS 버퍼 맨 끝에 널값 추가
	send_str(client, PASS);		//server에 password 전송
	char log[25];			//server에서 보낸 string을 저장할 버퍼
	int length;
	length=recv(client, log, 25, 0);//server에서 string 수신
	printf("%s\n", log);		//log 버퍼에 저장된 string 출력(성공인지 실패인지)
	loginchk = 0;
	//login 과정을 했으므로 다시 로그인 요청을 하지 않도록 loginchk에 0 반환
	if(strncmp(log, "401 LOGIN FAIL", 14)==0) exit(0);
	}//server에서 수신한 string이 실패의 메시지이면 client ftp를 종료


        int valid = 0;
        while (!valid) {
            valid = 1;
            printf("ftp >>> ");
            if (!fgets(line, BUF_SIZE, stdin)){
                running = 0;
                break;
            }
            int len = strlen(line);
            len --;
            while (line[len] == '\n' || line[len] == '\r') len--;
            len ++;
            line[len] = 0;
            enum USER_CMD cmd = parse_input_cmd(line, len);
            switch(cmd) {
                case USER_USER:
                case USER_PASS:
                case USER_TYPE:
                case USER_MKD:
                case USER_DELE:
                case USER_RNFR:
                case USER_RNTO:
                case USER_RMD:
                    send_str(client, "%s\r\n", line);
                    break;
                case USER_LS:
                    send_str(client, "PASV\r\n");
                    state = ST_PASVLIST;
                    break;
                case USER_CD:
                    send_str(client, "CWD %s\r\n", &line[3]);
                    break;
                case USER_PWD:
                    send_str(client, "PWD\r\n");
                    break;
                case USER_CDUP:
                    send_str(client, "CDUP\r\n");
                    break;
                case USER_HELP:
                    for (i=0; i<sizeof(USER_CMD_LIST)/sizeof(USER_CMD_LIST[0]); i++) {
                        printf("%s\n", USER_CMD_LIST[i].name);
                    }
                    valid = 0;
                    break;
                case USER_BYE:
                    send_str(client, "QUIT\r\n");
                    running = 0;
                    break;
                case USER_LCD:
                    chdir(&line[4]);
                    valid = 0;
                    break;
                case USER_LLS:
                    getcwd(path, sizeof(path));
                    printf("%s\n", path);

                    sprintf(cmdbuf, "ls -l %s", path);
                    FILE *p2 = popen(cmdbuf, "r");
                    int n;
                    while ((n=fread(tmpbuf, 1, BUF_SIZE, p2)) > 0 ) {
                        fwrite(tmpbuf, 1, n, stdout);
                    }
                    pclose(p2);

                    valid = 0;
                    break;
                case USER_LPWD:
                    getcwd(path, sizeof(path));
                    printf("%s\n", path);
                    valid = 0;
                    break;
                case USER_GET:
                    send_str(client, "PASV\r\n");
                    strcpy(filename, &line[4]);
                    state = ST_PASVGET;
                    break;
                case USER_PUT:
                    send_str(client, "PASV\r\n");
                    strcpy(filename, &line[4]);
                    state = ST_PASVPUT;
                    break;
                default:
                    warn(1, "unknown user cmd");
                    valid = 0;
                    break;
            }
        }
        if (!running) break;
    }
    int st = close(client);
    info(1, "FTP client close socket ... %d", st);
    info(1, "FTP client shutdown");
    if (data_client > 0) {
        st = close(data_client);
        info(1, "FTP client close data socket ... %d", st);
        info(1, "FTP client data socket shutdown");
    }
    return 0;
}

