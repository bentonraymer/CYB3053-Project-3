#include "io_helper.h"
#include "request.h"

#define MAXBUF (8192)

// below default values are defined in 'request.h'
int num_threads = DEFAULT_THREADS;
int scheduling_algo = DEFAULT_SCHED_ALGO;	



//
//	DONE: add code to create and manage the buffer
//


// Basic struct for request
typedef struct request {
  int fd;
  char *filename;
  int filesize;
} request_t;

// Struct for request buffer
typedef struct request_buffer {
  request_t *requests;
  int head; // Next item to be removed
  int tail; // Next item to be added
  int size;
  int capacity;
  pthread_mutex_t lock; // Lock to ensure mutual exclusion of buffer access 
  pthread_cond_t not_empty; // Condition variable to wait for requests
  pthread_cond_t not_full; // Condition variable to wait for space in the buffer
} request_buffer_t;

request_buffer_t buffer;

// Function to initialize the request buffer
void init_request_buffer(int capacity) {
  printf("DEBUG: Initializing buffer with capacity: %d\n", capacity);
  buffer.requests = malloc(sizeof(request_t) * capacity);
  buffer.head = 0;
  buffer.tail = 0;
  buffer.size = 0;
  buffer.capacity = capacity;
  pthread_mutex_init(&buffer.lock, NULL);
  pthread_cond_init(&buffer.not_empty, NULL); 
  pthread_cond_init(&buffer.not_full, NULL);
}

// Function to add item to the request buffer
int add_to_buffer(request_buffer_t *buffer, request_t request) {
  pthread_mutex_lock(&buffer->lock); // Lock the buffer for mutual exclusion
  while (buffer->size >= buffer->capacity ) { // Check to see if buffer is full
    pthread_cond_wait(&buffer->not_full, &buffer->lock); // Wait for space in buffer
  }
  buffer->requests[buffer->tail] = request; // Add request to the buffer
  buffer->tail = (buffer->tail + 1) % buffer->capacity; // Update tail value
  buffer->size++;
  pthread_cond_signal(&buffer->not_empty); // Indicate there's a request to be processed
  pthread_mutex_unlock(&buffer->lock); // Unlock
  printf("DEBUG: Request added to buffer\n");
  return 0;
}

int remove_from_buffer(request_buffer_t *buffer, request_t *request) {
  printf("DEBUG: Removing a request from buffer\n");
  pthread_mutex_lock(&buffer->lock); // Lock the buffer
  while (buffer->size == 0) {
    pthread_cond_wait(&buffer->not_empty, &buffer->lock); // Wait for requests
    printf("DEBUG: Buffer is full\n");
  }
  *request = buffer->requests[buffer->head]; // Remove request from the buffer
  printf("DEBUG: Request removed\n");
  buffer->head = (buffer->head + 1) % buffer->capacity; // Update head value
  buffer->size--; // Decrease buffer size
  printf("DEBUG: Updated head value and decreased buffer size\n");
  pthread_cond_signal(&buffer->not_full); // Space open in buffer
  pthread_mutex_unlock(&buffer->lock); // Unlock
  printf("DEBUG: All done removing!\n");
  return 0;
}

//
// Sends out HTTP response in case of errors
//
void request_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXBUF], body[MAXBUF];
    
    // Create the body of error message first (have to know its length for header)
    sprintf(body, ""
	    "<!doctype html>\r\n"
	    "<head>\r\n"
	    "  <title>CYB-3053 WebServer Error</title>\r\n"
	    "</head>\r\n"
	    "<body>\r\n"
	    "  <h2>%s: %s</h2>\r\n" 
	    "  <p>%s: %s</p>\r\n"
	    "</body>\r\n"
	    "</html>\r\n", errnum, shortmsg, longmsg, cause);
    
    // Write out the header information for this response
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Type: text/html\r\n");
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Length: %lu\r\n\r\n", strlen(body));
    write_or_die(fd, buf, strlen(buf));
    
    // Write out the body last
    write_or_die(fd, body, strlen(body));
    
    // close the socket connection
    close_or_die(fd);
}

//
// Reads and discards everything up to an empty text line
//
void request_read_headers(int fd) {
    char buf[MAXBUF];
    
    readline_or_die(fd, buf, MAXBUF);
    while (strcmp(buf, "\r\n")) {
		readline_or_die(fd, buf, MAXBUF);
    }
    return;
}

//
// Return 1 if static, 0 if dynamic content (executable file)
// Calculates filename (and cgiargs, for dynamic) from uri
//
int request_parse_uri(char *uri, char *filename, char *cgiargs) {
    char *ptr;
    
    if (!strstr(uri, "cgi")) { 
	// static
	strcpy(cgiargs, "");
	sprintf(filename, ".%s", uri);
	if (uri[strlen(uri)-1] == '/') {
	    strcat(filename, "index.html");
	}
	return 1;
    } else { 
	// dynamic
	ptr = index(uri, '?');
	if (ptr) {
	    strcpy(cgiargs, ptr+1);
	    *ptr = '\0';
	} else {
	    strcpy(cgiargs, "");
	}
	sprintf(filename, ".%s", uri);
	return 0;
    }
}

//
// Fills in the filetype given the filename
//
void request_get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html")) 
		strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif")) 
		strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg")) 
		strcpy(filetype, "image/jpeg");
    else 
		strcpy(filetype, "text/plain");
}

//
// Handles requests for static content
//
void request_serve_static(int fd, char *filename, int filesize) {
    int srcfd;
    char *srcp, filetype[MAXBUF], buf[MAXBUF];
    
    printf("DEBUG: Received Request\n");

    request_get_filetype(filename, filetype);
    srcfd = open_or_die(filename, O_RDONLY, 0);
    
    // Rather than call read() to read the file into memory, 
    // which would require that we allocate a buffer, we memory-map the file
    srcp = mmap_or_die(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close_or_die(srcfd);
    
    // put together response
    sprintf(buf, ""
	    "HTTP/1.0 200 OK\r\n"
	    "Server: OSTEP WebServer\r\n"
	    "Content-Length: %d\r\n"
	    "Content-Type: %s\r\n\r\n", 
	    filesize, filetype);
       
    printf("DEBUG: Message: %d\n", buf);

    write_or_die(fd, buf, strlen(buf));
    
    //  Writes out to the client socket the memory-mapped file 
    write_or_die(fd, srcp, filesize);
    munmap_or_die(srcp, filesize);
}



//
// Fetches the requests from the buffer and handles them (thread logic)
//
void* thread_request_serve_static(void* arg) {
  request_t req;

  printf("DEBUG: Worker thread started (algorithm=%d)\n", scheduling_algo);

  while (1) {
      request_t req;

      // Wait for request in the buffer
      pthread_mutex_lock(&buffer.lock);
      while (buffer.size == 0) {
          pthread_cond_wait(&buffer.not_empty, &buffer.lock);
      }

      int idx_in_queue = 0;
      // Handle according to scheduling algorithm
      // FIFO (First In, First Out)
      if (scheduling_algo == 0) {
          idx_in_queue = 0;
      // SFF (Shortest File First)
      } else if (scheduling_algo == 1){
        idx_in_queue = 0;
        int smallest_found = buffer.requests[buffer.head].filesize;
        // Loop through the buffer to find smallest file
        for (int i = 1; i < buffer.size; i++) {
          int idx = (buffer.head + 1) % buffer.capacity;
          if (buffer.requests[idx].filesize < smallest_found) {
            smallest_found = buffer.requests[idx].filesize;
            idx_in_queue = i;
            }
          }
      // RANDOM
      } else {
        idx_in_queue = rand() % buffer.size;
      }

      // Retrieve the proper request
      int real_idx = (buffer.head + idx_in_queue) % buffer.capacity;
      req = buffer.requests[real_idx];

      // Shift buffer to remove request
      if (idx_in_queue == 0) {
        buffer.head = (buffer.head + 1) % buffer.capacity;
      } else {
        for (int i = idx_in_queue; i < buffer.size - 1; i++) {
          int from = (buffer.head + i + 1) % buffer.capacity;
          int to = (buffer.head + i) % buffer.capacity;
          buffer.requests[to] = buffer.requests[from];
        }
        buffer.tail = (buffer.tail - 1 + buffer.capacity) % buffer.capacity;
      }

    // Update size and tail, signal, and unlock
    buffer.size--;
    pthread_cond_signal(&buffer.not_full);
    pthread_mutex_unlock(&buffer.lock);


    // Serve request
    printf("DEBUG: Serving %s fd=%d size=%d\n",req.filename, req.fd, req.filesize);
    request_serve_static(req.fd, req.filename, req.filesize);
    close(req.fd);
    free(req.filename);
  }
}

//
// Initial handling of the request
//
void request_handle(int fd) {
    int is_static;
    struct stat sbuf;
    char buf[MAXBUF], method[MAXBUF], uri[MAXBUF], version[MAXBUF];
    char filename[MAXBUF], cgiargs[MAXBUF];
    
	// get the request type, file path and HTTP version
    readline_or_die(fd, buf, MAXBUF);
    sscanf(buf, "%s %s %s", method, uri, version);
    printf("DEBUG: Request Received\n");
    printf("method:%s uri:%s version:%s\n", method, uri, version);

	// verify if the request type is GET or not
    if (strcasecmp(method, "GET")) {
      printf("DEBUG: GET Request Not Implemented\n");
      request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
      return;
    }
    request_read_headers(fd);
    
	// check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, filename, cgiargs);
    
	// get some data regarding the requested file, also check if requested file is present on server
    if (stat(filename, &sbuf) < 0) {
      printf("DEBUG: File not found\n");
      request_error(fd, filename, "404", "Not found", "server could not find this file");
      return;
    }
    
	// verify if requested content is static
    if (is_static) {
      if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
        request_error(fd, filename, "403", "Forbidden", "server could not read this file");
        return;
      }
		
		// DONE: write code to add HTTP requests in the buffer based on the scheduling policy


    printf("DEBUG: Adding request to buffer!\n");
    request_t req;
    req.fd = fd;
    req.filesize = sbuf.st_size;
    req.filename = strdup(filename);
    add_to_buffer(&buffer, req); // Add the request to the buffer


    } else {
		request_error(fd, filename, "501", "Not Implemented", "server does not serve dynamic content request");
    }
}



