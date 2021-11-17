FROM cs5231ta/cs5231-miniproj:v1

# additional dependencies of tools & testcases
RUN export DEBIAN_FRONTEND="noninteractive" && \
    apt-get update && apt-get -y install libsnappy-dev zlib1g-dev

# # more installation commands here if needed
# RUN export DEBIAN_FRONTEND="noninteractive" && \
#       apt-get build-dep qemu-system && \
#       apt-get -y install libacl1-dev

# RUN export DEBIAN_FRONTEND="noninteractive" && \
#       git clone git@github.com/angr/tracer.git && \
#       cd tracer && python3 setup.py  

# source mounted files
RUN echo "source /solution_mnt/bashrc" >> "/root/.bashrc" && \
    echo "source /solution_mnt/gdbinit" >> "/root/.gdbinit"

# keep container alive
CMD ["tail", "-f", "/dev/null"]
