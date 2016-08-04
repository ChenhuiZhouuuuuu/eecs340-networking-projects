#include "minet_socket.h"
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <string.h>

#define BUFSIZE 1024
#define FILENAMESIZE 100

int handle_connection(int);
int writenbytes(int,char *,int);
int readnbytes(int,char *,int);

int main(int argc,char *argv[])
{
  int server_port;
  int sock,sock2;
  struct sockaddr_in sa,sa2;
  int rc, i;
  fd_set readlist;

  int maxfd;

  /* parse command line args */
  if (argc != 3)
  {
    fprintf(stderr, "usage: http_server1 k|u port\n");
    exit(-1);
  }
  server_port = atoi(argv[2]);
  if (server_port < 1500)
  {
    fprintf(stderr,"INVALID PORT NUMBER: %d; can't be < 1500\n",server_port);
    exit(-1);
  }

  /* initialize and make socket */
  if (toupper(*(argv[1])) == 'K') {
    minet_init(MINET_KERNEL);
  } else if (toupper(*(argv[1])) == 'U') {
    minet_init(MINET_USER);
  } else {
    fprintf(stderr, "First argument must be k or u\n");
    exit(-1);
  }

  /* create socket */
  sock=minet_socket(SOCK_STREAM);
  maxfd = sock;

  /* set server address*/
  memset(&sa, 0, sizeof sa);
  sa.sin_port=htons(server_port);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_family=AF_INET;

  /* bind listening socket */
  minet_bind(sock, &sa);

  /* start listening */
  minet_listen(sock, 50);
  fprintf(stderr, "Server listening in port %d...\n", server_port);

  /* connection handling loop */
  while(1) {
    /* create read list */
    FD_ZERO(&readlist);
    FD_SET(sock, &readlist);

    /* do a select */
    if (minet_select(maxfd + 1, &readlist, NULL, NULL, NULL) < 0) {
      minet_perror("select error\n");
      exit(-1);
    }

    /* process sockets that are ready */
    for (i = 0; i <= maxfd; i++) {
      if (FD_ISSET(i, &readlist)) {
        /* for the accept socket, add accepted connection to connections */
        if (i == sock) {
          sock2 = minet_accept(sock, &sa2);
          if (sock2 > maxfd) {
            maxfd = sock2;
          }
          FD_SET(sock2, &readlist);
        /* for a connection socket, handle the connection */
        } else {
          if ((rc = handle_connection(i)) == -1) {
            fprintf(stderr, "Got an error when handling socket %d", rc);
          }
          FD_CLR(i, &readlist);
        }
      }
    }
  }

  minet_close(sock);
  minet_deinit();
}

int handle_connection(int sock2) {
  char filename[FILENAMESIZE+1];
  int rc;
  struct stat filestat;
  char buf[BUFSIZE+1];
  char *headers;
  char *bptr;
  int datalen=0;
  char *ok_response_f = "HTTP/1.0 200 OK\r\n"\
                      "Content-type: text/plain\r\n"\
                      "Content-length: %d \r\n\r\n";
  char *notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"\
                         "Content-type: text/html\r\n\r\n"\
                         "<html><body bgColor=black text=white>\n"\
                         "<h2>404 FILE NOT FOUND</h2>\n"\
                         "</body></html>\n";
  bool ok=true;

  /* first read loop -- get request and headers*/
  memset(buf, 0, BUFSIZE + 1);
  bptr = (char*) malloc(1);
  datalen = 0;
  char * bptr2;
  while ((rc = minet_read(sock2, buf, BUFSIZE)) > 0) {
    bptr = (char *) realloc(bptr, datalen + rc + 1);
    bptr2 = bptr + datalen;
    memset(bptr2, 0, rc + 1);
    for (int i = 0; i < rc; i++) {
      bptr2[i] = buf[i];
    }

    datalen += rc;
    memset(buf, 0, rc);

    if (strcmp(bptr + datalen - 4, "\r\n\r\n") == 0) {
      break;
    }
  }

  /* parse request to get file name */
  int i = 0;
  while (bptr[i++] != ' ');
  while (bptr[i++] == ' ');
  int start = i - 1;
  while (bptr[i++] != ' ');
  int end = i - 1;
  memset(filename, 0, FILENAMESIZE+1);
  strncpy(filename, bptr + start, end - start);

  /* Assumption: this is a GET request and filename contains no spaces*/
  /* try opening the file */

  if((rc = stat(filename, &filestat)) == -1) {
    ok = false;
  }

  /* send response */
  if (ok) {
    /* send headers */
    headers = (char*) malloc(strlen(ok_response_f) + 50);
    memset(headers, 0, strlen(ok_response_f) + 50);
    sprintf(headers, ok_response_f, filestat.st_size);
    writenbytes(sock2, headers, strlen(headers));
    free(headers);

    /* send file */
    fprintf(stderr, "Sending %s\n", filename);
    FILE * fp = fopen(filename, "r");
    fseek(fp, 0, SEEK_SET);
    memset(buf, 0, BUFSIZE + 1);
    while (fp != NULL) {
      rc = fread(buf, sizeof(char), BUFSIZE, fp);
      writenbytes(sock2, buf, rc);
      memset(buf, 0, rc);
      if (rc < BUFSIZE) {
        break;
      }
    }
    fclose(fp);
  } else {
    // send error response
    writenbytes(sock2, notok_response, strlen(notok_response));
  }

  /* close socket and free space */
  free(bptr);
  minet_close(sock2);

  if (ok) {
    return 0;
  } else {
    return -1;
  }
}

int readnbytes(int fd,char *buf,int size) {
  int rc = 0;
  int totalread = 0;
  while ((rc = minet_read(fd,buf+totalread,size-totalread)) > 0) {
    totalread += rc;
  }

  if (rc < 0) {
    return -1;
  } else {
    return totalread;
  }
}

int writenbytes(int fd,char *str,int size)
{
  int rc = 0;
  int totalwritten =0;
  while ((rc = minet_write(fd,str+totalwritten,size-totalwritten)) > 0) {
    totalwritten += rc;
  }

  if (rc < 0) {
    return -1;
  } else {
    return totalwritten;
  }
}

