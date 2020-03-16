REM run in current file dir
docker run -it --rm --name updateCert --env-file debug_env.txt --mount type=bind,source="${PWD}",target=/usr/src/app -w /usr/src/app node:12 node updateCert.js