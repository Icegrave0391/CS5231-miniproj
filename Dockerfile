FROM cs5231ta/cs5231-miniproj:v1

# additional dependencies of tools & testcases
RUN export DEBIAN_FRONTEND="noninteractive" && \
    apt-get update && apt-get -y install libsnappy-dev zlib1g-dev

# more installation commands here if needed
# RUN export DEBIAN_FRONTEND="noninteractive" && \
#   apt-get update &&  apt-get -y install ...

# source mounted files
RUN echo "source /solution_mnt/bashrc" >> "/root/.bashrc" && \
    echo "source /solution_mnt/gdbinit" >> "/root/.gdbinit"

# keep container alive
CMD ["tail", "-f", "/dev/null"]
