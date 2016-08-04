#include "minet_socket.h"
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>

#define BUFSIZE 1024

int write_n_bytes(int fd, char * buf, int count);
void print_n_bytes(FILE * wheretoprint, char * str, int n);

int main(int argc, char * argv[]) {
  char * server_name = NULL;
  int server_port = 0;
  char * server_path = NULL;

  int sock = 0;
  int rc = -1;
  int datalen = 0;
  bool ok = true;
  struct sockaddr_in sa;
  FILE * wheretoprint = stdout;
  struct hostent * site = NULL;
  char * req = NULL;

  char buf[BUFSIZE + 1];
  char * bptr = NULL;
  char * bptr2 = NULL;
  char * endheaders = NULL;

  fd_set set;

  /*parse args */
  if (argc != 5) {
    fprintf(stderr, "usage: http_client k|u server port path\n");
    exit(-1);
  }

  server_name = argv[2];
  server_port = atoi(argv[3]);
  server_path = argv[4];

  /* initialize minet */
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

  // Do DNS lookup
  site = gethostbyname(server_name);
  if (site == NULL) {
    fprintf(stderr, "Invalid Hostname\n");
    exit(-1);
  }
  struct in_addr inaddr;
  memcpy(&inaddr, site->h_addr_list[0], sizeof(struct in_addr));

  /* set address */
  memset(&sa, 0, sizeof sa);
  sa.sin_port=htons(server_port);
  sa.sin_addr = inaddr;
  sa.sin_family=AF_INET;

  /* connect socket */
  if (minet_connect(sock, &sa) == -1) {
    minet_perror("Connect failed\n");
    exit(-1);
  }

  /* send request */
  int length = strlen(server_path) + strlen(server_name) + 24;
  req = (char*) malloc(sizeof(char) * length + 1);
  memset(req, 0, length);
  sprintf(req, "GET %s HTTP/1.0\nHost: %s\r\n\r\n", server_path, server_name);

  if ((rc = write_n_bytes(sock, req, length)) == -1) {
    minet_perror("Write HTTP request to socket failed\n");
    exit(-1);
  }
  free(req);

  /* wait till socket can be read */
  /* Hint: use select(), and ignore timeout for now. */
  FD_ZERO(&set);
  FD_SET(sock, &set);

  if (minet_select(FD_SETSIZE, &set, NULL, NULL, NULL) < 0) {
    minet_perror("select error\n");
    exit(-1);
  }

  memset(buf, 0, BUFSIZE + 1);
  if (FD_ISSET(sock, &set)) {
    bptr = (char*) malloc(1);
    datalen = 0;
    while ((rc = minet_read(sock, buf, BUFSIZE)) > 0) {
      bptr = (char *) realloc(bptr, datalen + rc + 1);
      bptr2 = bptr + datalen;
      memset(bptr2, 0, rc + 1);
      for (int i = 0; i < rc; i++) {
        bptr2[i] = buf[i];
      }

      datalen += rc;
      memset(buf, 0, rc);
    }
  }

  // first read loop -- read headers
  endheaders = strstr(bptr, "\r\n\r\n");
  if (endheaders != NULL) {
    /* examine return code */
    //Skip "HTTP/1.0"
    int i = 0;
    while (bptr[i++] != ' ');
    while (bptr[i++] == ' ');
    int statusCode = atoi(bptr + i - 1);

    // Normal reply has return code 200
    if (statusCode != 200) {
      ok = false;
      wheretoprint = stderr;
    }

    /* print first part of response */
    int headerlen = endheaders - bptr + 2;
    print_n_bytes(wheretoprint, bptr, headerlen);
    fprintf(wheretoprint, "\n");

    /* print out the rest of the response */
    print_n_bytes(wheretoprint, bptr + headerlen + 4, datalen - headerlen - 4);
  } else {
    fprintf(stderr, "Parse response header failed\n");
    ok = false;
  }

  /*close socket and deinitialize */
  FD_CLR(sock, &set);
  minet_close(sock);
  minet_deinit();
  free(bptr);

  if (ok) {
    return 0;
  } else {
    return -1;
  }
}

void print_n_bytes(FILE * wheretoprint, char * str, int n) {
  for (int i = 0; i < n; i++) {
    if (str[i] != 0 && str[i] != '\r') {
      fprintf(wheretoprint, "%c", str[i]);
    }
  }
}

int write_n_bytes(int fd, char * buf, int count) {
  int rc = 0;
  int totalwritten = 0;

  while ((rc = minet_write(fd, buf + totalwritten, count - totalwritten)) > 0) {
    totalwritten += rc;
  }

  if (rc < 0) {
    return -1;
  } else {
    return totalwritten;
  }
}


