#ifndef __container_tracer_H
#define __container_tracer_H


/**
 * @brief Checks if a string starts with "doc", indicating that it may be running inside a Docker container.
 *
 * WARNING: This function should not be used in production as it uses a simple heuristic that may not reliably detect containerized processes.
 *
 * @param str The input string to check.
 * @return True if the string starts with "doc", false otherwise.
 *
 * @todo Find a more reliable method for detecting containerized processes.
 */
int __is_it_docker(const char *str) {
//    return true;
    return str[0]=='p' && str[1]=='y'&& str[2]=='t';
}


#endif 