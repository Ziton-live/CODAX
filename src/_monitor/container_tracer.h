#ifndef __container_tracer_H
#define __container_tracer_H


/**
@todo Find a better way to check if the files are python files. 
*/
int is_it_docker(const char *str) {
    return str[0]=='d' && str[1]=='o'&& str[2]=='c';
}

#endif 