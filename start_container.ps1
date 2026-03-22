
docker build -t forensics-sandbox -f docker\Dockerfile .\docker\
docker rm -f forensics
docker run -it --privileged --name forensics -v "${PWD}\evidence:/forensics_raw:ro" forensics-sandbox


#container: forensics
#imagem: forensics-sandbox