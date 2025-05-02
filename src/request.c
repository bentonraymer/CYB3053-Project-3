#include "io_helper.h"
#include "request.h"

#define MAXBUF (8192)


//
//	TODO: add code to create and manage the buffer
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
  int size;
  int capacity;
  pthread_mutex_t lock; // Lock to ensure mutual exclusion of buffer access 
  pthread_cond_t not_empty; // Condition variable to wait for requests
} request_buffer_t;

// Function to initialize the request buffer
void init_request_buffer(request_buffer_t *buffer, int capacity) {
  buffer->requests = malloc(sizeof(request_t) * capacity);
  buffer->size = 0;
  buffer->capacity = capacity;
  pthread_mutex_init(&buffer->lock, NULL);
  pthread_cond_init(&buffer->not_empty, NULL); 
}

// Function to add item to the request buffer
int add_to_buffer(request_buffer_t *buffer, request_t request) {
  pthread_mutex_lock(&buffer->lock); // Lock the buffer for mutual exclusion
  if (buffer->size >= buffer->capacity ) { // Check to see if buffer is full
    pthread_mutex_unlock(&buffer->lock) // Unlock
    return -1 // TODO: Determine whether we just kill it or keep waiting until buffer has room... unsure...
  }
  buffer->requests[buffer->size++] = *req; // Add request to the buffer
  pthread_cond_signal(&buffer->not_empty); // Indicate there's a request to be processed
  pthread_mutex_unlock(&buffer->lock); // Unlock
  return 0;
}

int remove_from_buffer(request_buffer_t *buffer, request_t *request) {
  pthread_mutex_lock(&buffer->lock); // Lock the buffer
  while (buffer->size == 0) {
    pthread_cond_wait(&buffer->not_empty, &buffer->lock); // Wait for requests
  }
  *req = buffer->requests[--buffer->size] // Remove request from the buffer
  pthread_mutex_unlock(&buffer->lock); // Unlock
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
       
    write_or_die(fd, buf, strlen(buf));
    
    //  Writes out to the client socket the memory-mapped file 
    write_or_die(fd, srcp, filesize);
    munmap_or_die(srcp, filesize);
}

//
// Fetches the requests from the buffer and handles them (thread logic)
//
void* thread_request_serve_static(void* arg)
{
	// TODO: write code to actualy respond to HTTP requests
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
    printf("method:%s uri:%s version:%s\n", method, uri, version);

	// verify if the request type is GET or not
    if (strcasecmp(method, "GET")) {
		request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
		return;
    }
    request_read_headers(fd);
    
	// check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, filename, cgiargs);
    
	// get some data regarding the requested file, also check if requested file is present on server
    if (stat(filename, &sbuf) < 0) {
		request_error(fd, filename, "404", "Not found", "server could not find this file");
		return;
    }
    
	// verify if requested content is static
    if (is_static) {
		if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
			request_error(fd, filename, "403", "Forbidden", "server could not read this file");
			return;
		}
		
		// TODO: write code to add HTTP requests in the buffer based on the scheduling policy




    } else {
		request_error(fd, filename, "501", "Not Implemented", "server does not serve dynamic content request");
    }
}



//
// Code to process requests in the buffer based on the three scheduling policies
//

    // FIFO (First In, First Out) - Process requests in the order that they come in
    void process_fifo(request_buffer_t *buffer) {
      request_t req;
      while (buffer->size > 0) {
          remove_from_buffer(buffer, &req); // Grab the first request from the buffer and dequeue it
          request_serve_static(req.fd, req.filename, req.filesize); // Handle request
      }
  }

  // SFF/SJF - Shortest File First / Shortest Job First
  void process_sff(request_buffer_t *buffer) {
      request_t req;
      while (buffer->size > 0 { // Loop until buffer is empty
          int min_found = 0; // Make a variable to set to the smallest found request
          for (int i = 1; i < buffer->size, i++) { // Loop through all items in the buffer
            if (buffer->requests[i].filesize < buffer->requests[min_found].filesize) // See if looped-through request is smaller than currently saved one
              min_found = i; // Set the smallest found request to the current one
          }
      }
      req = buffer->requests[min_found]; // Grab the request that was the smallest
      for (int i = min_found; i < buffer->size - 1; i++) { 
        buffer->requests[i] = buffer->requests[i + 1] // Shift all other requests
      }
      buffer->size--; // Shrink buffer
      request_serve_static(req.fd, req.filename, req.filesize); // Handle request
      
    )
  }

  // Random - Process requests / files in a random order
  void process_random(request_buffer_t *buffer) {
    request_t req;
    while (buffer->size > 0) { // Loop until buffer is empty
      int random_request = rand() % buffer_size; // Grab the index of a random request
      
    req = buffer->requests[random_request]; // Grab the request
    for (int i = random_index; i < buffer->size - 1; i++) {
      buffer->requests[i] = buffer->requests[i + 1]; // Shift all other requests
    }
    buffer->size--; // Shrink buffer

    request_serve_static(req.fd, req.filename, req.filesize); // Handle request
  }
  }