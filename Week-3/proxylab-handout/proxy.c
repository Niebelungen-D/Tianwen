#include <stdio.h>
#include "csapp.h"


/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define MAX_OBJECT_COUNT 10


typedef struct cache_block
{
    char *uri;
    char *data;

    //int64_t last_modified_time; 
    //How to deal with it when one thread wants to modify it, while another thread is reading it?

}cache_block;


typedef struct
{
    int  cache_count;
    cache_block *cache_list;

}Cache;


void doit(int fd);
int parse_uri(char *uri, char *hostname,char *path, int* port);
void build_http_header(char *header,char *hostname,char *path,int port,rio_t *rio); 
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);
void *thread(void *vargp);
void cache_init();
int reader(int fd, char *uri);
void writer(char *uri, char *buf);


/* You won't lose style points for including this long line in your code */
static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";
static const char *conn_hdr = "Connection: close\r\n";
static const char *prox_hdr = "Proxy-Connection: close\r\n";

Cache cache;
sem_t mutex, w;
int readcnt;

int main(int argc, char **argv)
{
    int listenfd, *connfd;
    char hostname[MAXLINE], port[MAXLINE];
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    pthread_t tid;


    /* check command line args */
    if(argc !=2){ 
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
	exit(1);
    }
    cache_init();
    listenfd = Open_listenfd(argv[1]);
    while(1) {
        clientlen = sizeof(clientaddr);
        connfd = Malloc(sizeof(int));
        *connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
        Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, port, MAXLINE, 0);
        printf("Accepted connection from (%s, %s)\n", hostname, port);
        Pthread_create(&tid,NULL,thread,connfd);
    }

    //printf("%s", user_agent_hdr);
    return 0;
}


/*
 * doit - handle one HTTP request/sennd it to server
 */
void doit(int fd) 
{
    int end_serverfd;
    struct stat sbuf;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE],obj_buf[MAXLINE];
    char filename[MAXLINE], end_server_header[MAXLINE],hostname[MAXLINE],path[MAXLINE];
    int port, size;
    rio_t rio,rio_end;
    int total=0;

    /* Read request line and headers */
    Rio_readinitb(&rio, fd);
    if (!Rio_readlineb(&rio, buf, MAXLINE))  //line:netp:doit:readrequest
        return;
    printf("%s", buf);
    sscanf(buf, "%s %s %s", method, uri, version);       //line:netp:doit:parserequest
    if (strcasecmp(method, "GET")) {                     //line:netp:doit:beginrequesterr
        clienterror(fd, method, "501", "Not Implemented",
                    "Proxy does not implement this method");
        return;
    }                                                    //line:netp:doit:endrequesterr
    parse_uri(uri,hostname,path,&port);            
    if(reader(fd,uri)) {
        return;
    }
    else {
        char port_str[10];
        sprintf(port_str,"%d",port);    //int to str

        end_serverfd = Open_clientfd(hostname,port_str);    //connect with server
        if(end_serverfd<0){
            printf("connextion failed.\n");
            return;
        }

        build_http_header(end_server_header,hostname,path,port,&rio);         //build http header as a client
        Rio_readinitb(&rio_end, end_serverfd);
        Rio_writen(end_serverfd, end_server_header,strlen(end_server_header));//send header to server

        while((size=Rio_readlineb(&rio_end, buf, MAXLINE))!=0)  //recv from server
        {
            printf("Proxy recv %d bytes data and send to client\n",size);
            Rio_writen(fd,buf,size);                        //send back to client
            //strcpy(obj_buf+total,buf);
            //total += size;
        }
        /*if (total < MAX_OBJECT_SIZE) {
            writer(uri, obj_buf);
        }*/
        Close(end_serverfd);            //close connection to server
    }
}



/*
 * parse_uri - parse URI into filename
 */
/* $begin parse_uri */
int parse_uri(char *uri, char *hostname, char *path, int* port) 
{
    *port = 80;
    char *p1,*p2;
    if((p1=strstr(uri,"//"))!=NULL) //  http://hostname:port/xxxx/xxxx
        p1=p1+2;
    else
        p1=uri;                 //   hostname:port/xxxx/xxxx

    p2=strstr(p1,":");
    if(p2==NULL)  { 
        p2=strstr(p1,"/");      //   /xxxx/xxxx
        if(p2!=NULL) {          //   hostname/xxxx/xxxx
            *p2='\0';
            sscanf(p1,"%s",hostname);
            *p2='/';
            sscanf(p2,"%s",path);
        }
        else {                  //   hostname
            sscanf(p1,"%s",hostname);
        }
    }
    else {
        *p2='\0';
        sscanf(p1,"%s",hostname);   //  hostname:port/xxxx/xxxx
        sscanf(p2+1,"%d%s",port,path);
    }

}
/* $end parse_uri */

void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg) 
{
    char buf[MAXLINE];

    /* Print the HTTP response headers */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-type: text/html\r\n\r\n");
    Rio_writen(fd, buf, strlen(buf));

    /* Print the HTTP response body */
    sprintf(buf, "<html><title>Tiny Error</title>");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<body bgcolor=""ffffff"">\r\n");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "%s: %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<p>%s: %s\r\n", longmsg, cause);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "<hr><em>The Tiny Web server</em>\r\n");
    Rio_writen(fd, buf, strlen(buf));
}


void build_http_header(char *http_header,char *hostname,char *path,int port,rio_t *rio)
{
    char buf[MAXLINE],request_hdr[MAXLINE],host_hdr[MAXLINE], connection_hdr[MAXLINE],proxy_hdr[MAXLINE];

    sprintf(request_hdr,"GET %s HTTP/1.0\r\n",path);    //request_hdr
    while(Rio_readlineb(rio,buf,MAXLINE)>0) {
        if(!strcmp(buf,"\r\n")) {
            break;
        }

        if(!strncasecmp(buf,"Host:",strlen("Host:"))) {     //host
            strcpy(host_hdr,buf);
            continue;
        }

    }
    if(strlen(host_hdr)==0)
    {
        sprintf(host_hdr,"Host: %s\r\n",hostname);
    }

    sprintf(http_header,"%s%s%s%s%s%s",request_hdr,host_hdr,user_agent_hdr,connection_hdr,prox_hdr,"\r\n");
    return ;

}

void *thread(void *vargp) {
    int connfd = *((int *)vargp);
    Pthread_detach(pthread_self());
    //Free(connfd);  
    doit(connfd);
    Close(connfd);
    return NULL;
}


void cache_init() {
    Sem_init(&mutex, 0, 1);
    Sem_init(&w, 0, 1);
    readcnt = 0;
    cache.cache_count=0;
    cache.cache_list=(cache_block *)Malloc(MAX_OBJECT_COUNT*sizeof(cache_block));
    for (int i = 0; i < 10; ++i) {
        cache.cache_list[i].uri = Malloc(sizeof(char) * MAXLINE);
        cache.cache_list[i].data = Malloc(sizeof(char) * MAX_OBJECT_SIZE);
    }
}

int reader(int fd, char *uri) {
    int in_cache= 0;
    P(&mutex);
    readcnt++;
    if (readcnt == 1) {
        P(&w);
    }
    V(&mutex);

    for (int i = 0; i < 10; ++i) {
        if (!strcmp(cache.cache_list[i].uri, uri)) {
            Rio_writen(fd, cache.cache_list[i].data, MAX_OBJECT_SIZE);
            in_cache = 1;
            break;
        }
    }
    P(&mutex);
    readcnt--;
    if (readcnt == 0) {
        V(&w);
    }
    V(&mutex);
    return in_cache;
}

void writer(char *uri, char *buf) {
    P(&w);
    strcpy(cache.cache_list[cache.cache_count].uri, uri);
    strcpy(cache.cache_list[cache.cache_count].data, buf);
    cache.cache_count++;
    V(&w);
}
