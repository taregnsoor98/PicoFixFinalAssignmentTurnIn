#include "httpd.h"
#include <sys/stat.h>
#include <syslog.h>

#define CHUNK_SIZE 1024 // read 1024 bytes at a time

// Public directory settings
#define PUBLIC_DIR "./webroot"
#define INDEX_HTML "/index.html"
#define NOT_FOUND_HTML "/404.html"

int main(int c, char **v) {
  char *port = c == 1 ? "8000" : v[1];

  // Open connection to syslog with identifier "foxweb"
  // LOG_PID adds the process ID; LOG_CONS ensures messages go to console on error;
  // LOG_DAEMON indicates the daemon facility.
  openlog("foxweb", LOG_PID | LOG_CONS, LOG_DAEMON);

  // Log the startup information: the port and the resource directory.
  // PUBLIC_DIR is defined earlier in the file (e.g., "./webroot")
  syslog(LOG_INFO, "Service started on port %s, resource directory: %s", port, PUBLIC_DIR);

  // Start the server; this is the blocking call that runs the service.
  serve_forever(port);

  // If serve_forever returns (on service shutdown), close the syslog connection.
  closelog();

  return 0;
}

int file_exists(const char *file_name) {
  struct stat buffer;
  int exists;

  exists = (stat(file_name, &buffer) == 0);

  return exists;
}

int read_file(const char *file_name) {
  char buf[CHUNK_SIZE];
  FILE *file;
  size_t nread;
  int err = 1;

  file = fopen(file_name, "r");

  if (file) {
    while ((nread = fread(buf, 1, sizeof buf, file)) > 0)
      fwrite(buf, 1, nread, stdout);

    err = ferror(file);
    fclose(file);
  }
  return err;
}

void route() {
  ROUTE_START()

  GET("/") {
    char index_html[50];
    snprintf(index_html, sizeof(index_html), "%s%s", PUBLIC_DIR, INDEX_HTML);

    HTTP_200;
    if (file_exists(index_html)) {
      read_file(index_html);
    } else {
      printf("Hello! You are using %s\n\n", request_header("User-Agent"));
    }
  }

  GET("/test") {
    HTTP_200;
    printf("List of request headers:\n\n");

    header_t *h = request_headers();

    while (h->name) {
      printf("%s: %s\n", h->name, h->value);
      h++;
    }
  }

  POST("/") {
    HTTP_201;
    printf("Wow, seems that you POSTed %d bytes.\n", payload_size);
    printf("Fetch the data using `payload` variable.\n");
    if (payload_size > 0)
      printf("Request body: %s", payload);
  }

  GET(uri) {
    char file_name[255];
    sprintf(file_name, "%s%s", PUBLIC_DIR, uri);

    if (file_exists(file_name)) {
      HTTP_200;
      read_file(file_name);
    } else {
      HTTP_404;
      sprintf(file_name, "%s%s", PUBLIC_DIR, NOT_FOUND_HTML);
      if (file_exists(file_name))
        read_file(file_name);
    }
  }

  ROUTE_END()
}
