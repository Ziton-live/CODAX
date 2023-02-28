#ifndef __container_tracer_H
#define __container_tracer_H


/**
@todo Find a better way to check if the files are python files. 
*/
int starts_with_python(const char *str) {
    return str[0]=='p' && str[1]=='y'&& str[2]=='t';
}

#endif 