
docker build -t forensics-sandbox -f docker\Dockerfile .\docker\
docker rm -f forensics_sandbox 
docker run -dit --name forensics_sandbox -v "${PWD}\evidence:/forensics_raw:ro" forensics-sandbox