
docker build -t forensics-sandbox -f docker\Dockerfile .\docker\
docker rm -f forensics
docker run -it --rm --cap-add SYS_ADMIN --cap-add MKNOD --device /dev/loop-control --device /dev/fuse --device-cgroup-rule 'b 7:* rmw' --name forensics -v "${PWD}\evidence:/forensics_raw:ro" forensics-sandbox


#container: forensics
#imagem: forensics-sandbox

#corre o entrypoint