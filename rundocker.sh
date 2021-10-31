#!/bin/bash
SID=$(cat ./SID)
if [ "$SID" = "e0123456:" ]; then
  echo "SID is still the placeholder."
  echo "Please copy your ~/A2/SID file here to replace ./SID"
  echo "Make sure the SID file content has the format eXXXXXXX:"
  exit 1
fi

if [ $USER != "student" ]; then
  echo "Please run as student."
  exit
fi

TARGET=$1
if [ -z "$TARGET" ]; then
TARGET="help"
fi

if [ $TARGET = "help" ]; then
echo "Docker Runner For CS5231-2021Fall Mini Project ($SID)"
echo "Usage: ./rundocker.sh <COMMAND>"
echo "Available commands:"
echo ""
echo "  build           | Build Docker Image from Dockerfile"
echo "  run             | Run a container from image"
echo "  shell           | Start a bash shell inside the container (if it is running)"
echo "  stop            | Stop the running container"
echo "  clean           | Clean up dangling images and stopped containers"
echo "  status          | Print status of docker images and containers"
echo ""
exit
fi

if [ $TARGET = "build" ]; then
echo "----- Remove stopped container -----"
container_list=$(docker container ls -a -q)
if [[ -n "${container_list// /}" ]]; then
  docker container rm $(docker container ls -a -q)
fi
echo "----- Build Docker Image -----"
docker image rm cs5231-miniproj-${SID:0:8}:v1
docker build -t cs5231-miniproj-${SID:0:8}:v1 -f ./Dockerfile .
exit
fi

if [ $TARGET = "run" ]; then
echo "----- Remove stopped container -----"
container_list=$(docker container ls -a -q)
if [[ -n "${container_list// /}" ]]; then
  docker container rm $(docker container ls -a -q)
fi
echo "----- Create Temporary Container from Image and Start -----"
testcases_mnt_dir=/home/student/miniproj/testcases_mnt
dynamorio_dir=/home/student/proj_tools/DynamoRIO
dev_private_data_dir=/home/student/miniproj/dev_private_data
docker run --init --name cs5231_${SID:0:8}_container -d -t \
  --mount type=bind,source=$PWD/solution_mnt,target=/solution_mnt \
  --mount type=bind,source=$testcases_mnt_dir,target=/testcases_mnt,readonly \
  --mount type=bind,source=$dynamorio_dir,target=/root/DynamoRIO,readonly \
  --mount type=bind,source=$dev_private_data_dir/ssh_mnt,target=/root/.ssh \
  --mount type=bind,source=$dev_private_data_dir/peda_mnt,target=/root/peda \
  --mount type=bind,source=$dev_private_data_dir/vscode_server_mnt,target=/root/.vscode-server \
  -p 127.0.0.1:10022:22/tcp \
  cs5231-miniproj-${SID:0:8}:v1
docker exec cs5231_${SID:0:8}_container chmod 700 /root/.ssh
docker exec cs5231_${SID:0:8}_container chown root:root /root/.ssh
docker exec cs5231_${SID:0:8}_container chown root:root /root/.vscode-server
docker exec -d cs5231_${SID:0:8}_container service ssh start
echo "--- NOTE: All private data under $dev_private_data_dir will not be mounted in Online Judge."
echo "--- NOTE: To mount more persistent folders during development, modify ./rundocker.sh to add more private data folder mounting points."
echo "--- NOTE: To install more dependencies of your solution in the docker image, add RUN commands in ./Dockerfile"
echo "--- NOTE: To stop the container, use ./rundocker.sh stop"
exit
fi

if [ $TARGET = "shell" ]; then
docker exec -it cs5231_${SID:0:8}_container /bin/bash
exit
fi

if [ $TARGET = "edit-authkeys" ]; then
docker exec -it cs5231_${SID:0:8}_container vim /root/.ssh/authorized_keys
docker exec -it cs5231_${SID:0:8}_container chmod 600 /root/.ssh/authorized_keys
exit
fi

if [ $TARGET = "stop" ]; then
echo "----- Stop Container (send signal and wait) -----"
echo "--- Please wait for several seconds."
docker stop cs5231_${SID:0:8}_container
docker container ls
exit
fi

if [ $TARGET = "status" ]; then
echo "---------- images ----------"
docker image ls
echo ""
echo "--- layers of image cs5231-miniproj-${SID:0:8}:v1 ---"
docker history cs5231-miniproj-${SID:0:8}:v1
echo ""
echo "-------- temporary containers --------"
docker container ls --size
exit
fi

if [ $TARGET = "clean" ]; then
  echo "----- Remove stopped containers -----"
  container_list=$(docker container ls -a -q)
  if [[ -n "${container_list// /}" ]]; then
    docker container rm $(docker container ls -a -q)
  fi
  echo "----- Remove dangling images -----"
  dangling_images=$(docker images --filter "dangling=true" -q --no-trunc)
  if [ ! -z $dangling_images ]; then
    docker rmi $dangling_images
  fi
  exit
fi

# below for TA -----------------------------------------
# Create a container from image and start it (eval setting, for TA)

if [ $TARGET = "run-eval" ]; then
echo "----- Remove stopped container -----"
container_list=$(docker container ls -a -q)
if [[ -n "${container_list// /}" ]]; then
  docker container rm $(docker container ls -a -q)
fi
echo "----- Create Temporary Eval Container from Image and Start -----"
testcases_mnt_dir=/home/student/miniproj/testcases_mnt
dynamorio_dir=/home/student/proj_tools/DynamoRIO
docker run --init --name cs5231_${SID:0:8}_container -d -t \
  --network none \
  --memory 4g \
  --cpus 1 \
  --mount type=bind,source=$PWD/solution_mnt,target=/solution_mnt \
  --mount type=bind,source=$testcases_mnt_dir,target=/testcases_mnt,readonly \
  --mount type=bind,source=$dynamorio_dir,target=/root/DynamoRIO,readonly \
  cs5231-miniproj-${SID:0:8}:v1
echo "--- To stop the container, use ./rundocker.sh stop"
exit
fi

echo "Unknown command. See ./rundocker.sh help"