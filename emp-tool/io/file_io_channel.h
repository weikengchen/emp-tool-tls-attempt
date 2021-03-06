#ifndef FILE_IO_CHANNEL_H__
#define FILE_IO_CHANNEL_H__

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <unistd.h>
//#include <arpa/inet.h>
//#include <sys/types.h>
//#include <netinet/in.h>
//#include <sys/socket.h>
#include <string>
#include "io_channel.h"
using namespace std;

/** @addtogroup IO
    @{
  */
  
class FileIO: public IOChannel<FileIO> { public:
	uint64_t bytes_sent = 0;
	int mysocket = -1;
	FILE * stream = nullptr;
	char * buffer = nullptr;
	FileIO(const char * file, bool read) {
		if (read)
			stream = fopen(file, "rb+");
		else
			stream = fopen(file, "wb+");
		buffer = new char[FILE_BUFFER_SIZE];
		memset(buffer, 0, FILE_BUFFER_SIZE);
		setvbuf(stream, buffer, _IOFBF, FILE_BUFFER_SIZE);
	}

	~FileIO(){
		fflush(stream);
		fclose(stream);
		delete[] buffer;
	}

	void flush() {
		fflush(stream);
	}

	void reset() {
		rewind(stream);
	}
	void send_data_impl(const void * data, int len) {
		bytes_sent += len;
        size_t sent = 0;
		while(sent < len) {
			auto res = fwrite(sent+(char*)data, 1, len-sent, stream);
			if (res >= 0)
				sent+=res;
			else
				fprintf(stderr,"error: file_send_data %d\n", (int)res);
		}
	}
	void recv_data_impl(void  * data, int len) {
		size_t sent = 0;
		while(sent < len) {
			auto res = fread(sent+(char*)data, 1, len-sent, stream);
			if (res >= 0)
				sent+=res;
			else 
				fprintf(stderr,"error: file_recv_data %d\n", (int)res);
		}
	}
};
/**@}*/
#endif//FILE_IO_CHANNEL
