# DOCKER NOTES
- pull and run an nginx server
`docker run --publish 80:80 --name server nginx`
- List all running containers
`docker ps` -a for a list of idle containers
- `docker stop  nginx`
- `docker rm nginx`

attach shell
docker run -it <container name> -- </bin/bash>

Running containers
docker container exec -it <container name> -- bash


docker images // list images 
docker rmi <image name> // image removed
docker system prune -a // all images currently not in use


Build
docker build -t [image:tag] -f [filename] // . can be given



Storing Data 

docker  volume create <volume name>
docker volume ls
docker volume inspect <volume name>
docker volume rm <volume name>
docker volume prune






compose file
```yaml
version: '3.9'
    services:
        webapi1:
            image: academy. azurecr.io/webapi1
            ports:
                -'8081:80
            restart: always
    webapi2:
        image: academy.azurecr.io/webapi2
        ports:
            - '8082:80'
        restart: always
    apigateway:
        image: academy. azurecr.io/apigateway
        ports:
            - '80:80'
        restart: always
```