#ifndef __container_tracer_H
#define __container_tracer_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define PRODUCTION 0

int starts_with_python(const char *str) {
    return str[0]=='p' && str[1]=='y'&& str[2]=='t';
}

#endif 