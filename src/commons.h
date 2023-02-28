#ifndef __commons_H
#define __commons_H
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127





#define PRODUCTION 0

struct connectionDescriptor {
	int pid;
	u64 elapsed_time_ns;
	u64 start_time;
	char filename[MAX_FILENAME_LEN];
};


#endif 