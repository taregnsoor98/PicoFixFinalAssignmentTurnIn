#include "httpd.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <sqlite3.h>
#include <openssl/md5.h>

#define MAX_CONNECTIONS 1000
#define BUF_SIZE 65535
#define QUEUE_SIZE 1000000

static int listenfd;
int *clients;
static void start_server(const char *);
static void respond(int);

// Send a 401 Unauthorized response with Digest challenge
void send_401_unauthorized() {
    printf("HTTP/1.1 401 Unauthorized\r\n");
    printf("WWW-Authenticate: Digest realm=\"Foxweb\", qop=\"auth\", nonce=\"abcdef\", opaque=\"12345\"\r\n");
    printf("Content-Type: text/html\r\n");
    printf("\r\n");
    printf("<html><body><h1>401 Unauthorized</h1></body></html>\r\n");
}

static char *buf;

void log_http_request(const char *client_ip, const char *method, const char *uri, int status_code, long data_size) {
      FILE *log_file = fopen("foxweb.log", "a");
if (!log_file) {
      perror("Failed to open log file");
      return;
  }
  char timestamp[64];
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  strftime(timestamp, sizeof(timestamp), "[%d/%b/%Y:%H:%M:%S %z]", tm_info);

  // Write a log entry in Combined Log Format style.
  fprintf(log_file, "%s - - %s \"%s %s HTTP/1.1\" %d %ld\n", client_ip, timestamp, method, uri, status_code, data_size);
  fclose(log_file);
}

// Client request
char *method, // "GET" or "POST"
    *uri,     // "/index.html" things before '?'
    *qs,      // "a=1&b=2" things after  '?'
    *prot,    // "HTTP/1.1"
    *payload; // for POST

int payload_size;

void serve_forever(const char *PORT) {
  struct sockaddr_in clientaddr;
  socklen_t addrlen;

  int slot = 0;

  printf("Server started %shttp://127.0.0.1:%s%s\n", "\033[92m", PORT,
         "\033[0m");

  // create shared memory for client slot array
  clients = mmap(NULL, sizeof(*clients) * MAX_CONNECTIONS,
                 PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

  // Setting all elements to -1: signifies there is no client connected
  int i;
  for (i = 0; i < MAX_CONNECTIONS; i++)
    clients[i] = -1;
  start_server(PORT);

  // Ignore SIGCHLD to avoid zombie threads
  signal(SIGCHLD, SIG_IGN);

  // ACCEPT connections
  while (1) {
    addrlen = sizeof(clientaddr);
    clients[slot] = accept(listenfd, (struct sockaddr *)&clientaddr, &addrlen);

    if (clients[slot] < 0) {
      perror("accept() error");
      exit(1);
    } else {
      if (fork() == 0) {
        close(listenfd);
        respond(slot);
        close(clients[slot]);
        clients[slot] = -1;
        exit(0);
      } else {
        close(clients[slot]);
      }
    }

    while (clients[slot] != -1)
      slot = (slot + 1) % MAX_CONNECTIONS;
  }
}

// start server
void start_server(const char *port) {
  struct addrinfo hints, *res, *p;

  // getaddrinfo for host
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, port, &hints, &res) != 0) {
    perror("getaddrinfo() error");
    exit(1);
  }
  // socket and bind
  for (p = res; p != NULL; p = p->ai_next) {
    int option = 1;
    listenfd = socket(p->ai_family, p->ai_socktype, 0);
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    if (listenfd == -1)
      continue;
    if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
      break;
  }
  if (p == NULL) {
    perror("socket() or bind()");
    exit(1);
  }

  freeaddrinfo(res);

  // listen for incoming connections
  if (listen(listenfd, QUEUE_SIZE) != 0) {
    perror("listen() error");
    exit(1);
  }
}

// get request header by name
char *request_header(const char *name) {
  header_t *h = reqhdr;
  while (h->name) {
    if (strcmp(h->name, name) == 0)
      return h->value;
    h++;
  }
  return NULL;
}

// get all request headers
header_t *request_headers(void) { return reqhdr; }

// Handle escape characters (%xx)
static void uri_unescape(char *uri) {
  char chr = 0;
  char *src = uri;
  char *dst = uri;

  // Skip inital non encoded character
  while (*src && !isspace((int)(*src)) && (*src != '%'))
    src++;

  // Replace encoded characters with corresponding code.
  dst = src;
  while (*src && !isspace((int)(*src))) {
    if (*src == '+')
      chr = ' ';
    else if ((*src == '%') && src[1] && src[2]) {
      src++;
      chr = ((*src & 0x0F) + 9 * (*src > '9')) * 16;
      src++;
      chr += ((*src & 0x0F) + 9 * (*src > '9'));
    } else
      chr = *src;
    *dst++ = chr;
    src++;
  }
  *dst = '\0';
}

// client connection 
void respond(int slot) {
  int rcvd;

  buf = malloc(BUF_SIZE);
  
  // Capture client's IP address
  char client_ip[INET_ADDRSTRLEN] = "unknown";
  struct sockaddr_in peer_addr;
  socklen_t peer_len = sizeof(peer_addr);
  if (getpeername(clients[slot], (struct sockaddr *)&peer_addr, &peer_len) == 0) {
      inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip, sizeof(client_ip));
  }
  
  rcvd = recv(clients[slot], buf, BUF_SIZE, 0);

  if (rcvd < 0) // receive error
    fprintf(stderr, ("recv() error\n"));
  else if (rcvd == 0) // receive socket closed
    fprintf(stderr, "Client disconnected upexpectedly.\n");
  else // message received
  {
    buf[rcvd] = '\0';

    method = strtok(buf, " \t\r\n");
    uri = strtok(NULL, " \t");
    prot = strtok(NULL, " \t\r\n");

    uri_unescape(uri);

    fprintf(stderr, "\x1b[32m + [%s] %s\x1b[0m\n", method, uri);

    qs = strchr(uri, '?');

    if (qs)
      *qs++ = '\0'; // split URI
    else
      qs = uri - 1; // use an empty string

    header_t *h = reqhdr;
    char *t, *t2;
    while (h < reqhdr + 16) {
      char *key, *val;

      key = strtok(NULL, "\r\n: \t");
      if (!key)
        break;

      val = strtok(NULL, "\r\n");
      while (*val && *val == ' ')
        val++;

      h->name = key;
      h->value = val;
      h++;
      fprintf(stderr, "[H] %s: %s\n", key, val);
      t = val + 1 + strlen(val);
      if (t[1] == '\r' && t[2] == '\n')
        break;
    }
    t = strtok(NULL, "\r\n");
    t2 = request_header("Content-Length"); // and the related header if there is
    payload = t;
    payload_size = t2 ? atol(t2) : (rcvd - (t - buf));

    // bind clientfd to stdout, making it easier to write
    int clientfd = clients[slot];
    dup2(clientfd, STDOUT_FILENO);
    close(clientfd);

     // Check if Authorization header is missing
    char *auth_header = request_header("Authorization");
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_open("users.db", &db);
    if (rc) {
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    send_401_unauthorized();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buf);
    return;
    }

    if (!auth_header) {
        send_401_unauthorized();
        fflush(stdout);
        shutdown(STDOUT_FILENO, SHUT_WR);
        close(STDOUT_FILENO);
        free(buf);
        return;
    }

    // Try to extract the username from the Authorization header
    char *user_start = strstr(auth_header, "username=\"");
    if (!user_start) {
    send_401_unauthorized();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buf);
    return;
    }
    user_start += 10; // skip username="

    char *user_end = strchr(user_start, '"');
    if (!user_end) {
    send_401_unauthorized();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buf);
    return;
    }

   char username[256] = {0};
   strncpy(username, user_start, user_end - user_start);

    // Prepare SQL query to get HA1 hash for the username
    const char *sql = "SELECT ha1 FROM users WHERE username = ?;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
    send_401_unauthorized();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buf);
    return;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
    // Username not found
    send_401_unauthorized();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buf);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return;
    }

    // Get stored HA1 value
    const unsigned char *stored_ha1 = sqlite3_column_text(stmt, 0);
    
    // Now extract the response value from Authorization header
    char *response_start = strstr(auth_header, "response=\"");
    if (!response_start) {
    send_401_unauthorized();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buf);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return;
    }
    response_start += 10; // skip response="

    char *response_end = strchr(response_start, '"');
    if (!response_end) {
    send_401_unauthorized();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buf);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return;
    }

    char response_received[256] = {0};
    strncpy(response_received, response_start, response_end - response_start);

    // Extract nonce
char *nonce_start = strstr(auth_header, "nonce=\"");
if (!nonce_start) { send_401_unauthorized(); /*…cleanup…*/ return; }
nonce_start += 7;
char *nonce_end = strchr(nonce_start, '"');
char nonce[256] = {0};
strncpy(nonce, nonce_start, nonce_end - nonce_start);

// Extract nc
char *nc_start = strstr(auth_header, "nc=");
char nc[9] = {0};
if (nc_start) {
    strncpy(nc, nc_start+3, 8);
}

// Extract cnonce
char *cnonce_start = strstr(auth_header, "cnonce=\"");
char cnonce[256] = {0};
if (cnonce_start) {
    cnonce_start += 8;
    char *cnonce_end = strchr(cnonce_start, '"');
    strncpy(cnonce, cnonce_start, cnonce_end - cnonce_start);
}

// Hard-code qop
char qop[] = "auth";

// Compute HA2 = MD5(method:uri)
unsigned char ha2_bin[MD5_DIGEST_LENGTH];
char ha2_str[33] = {0};
char ha2_input[BUF_SIZE];
snprintf(ha2_input, sizeof(ha2_input), "%s:%s", method, uri);
MD5((unsigned char*)ha2_input, strlen(ha2_input), ha2_bin);
for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(ha2_str + i*2, "%02x", ha2_bin[i]);
}

// Compute expected response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
unsigned char resp_bin[MD5_DIGEST_LENGTH];
char resp_str[33] = {0};
char resp_input[BUF_SIZE];
snprintf(resp_input, sizeof(resp_input), "%s:%s:%s:%s:%s:%s",
         (const char*)stored_ha1, nonce, nc, cnonce, qop, ha2_str);
MD5((unsigned char*)resp_input, strlen(resp_input), resp_bin);
for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    sprintf(resp_str + i*2, "%02x", resp_bin[i]);
}

// Compare calculated vs. received response
if (strcmp(resp_str, response_received) != 0) {
    send_401_unauthorized();
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buf);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return;
}

    // Success - username and hash match
    sqlite3_finalize(stmt);
    sqlite3_close(db);


    // call router
    route();
    log_http_request(client_ip, method, uri, 200, 0);

    // tidy up
    fflush(stdout);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
  }

  free(buf);
  }
