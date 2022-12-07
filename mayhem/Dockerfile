FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake pkg-config libzip-dev libyaml-dev wget clang

RUN wget https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/libelf/0.8.13-5/libelf_0.8.13.orig.tar.gz -O lb.tar.gz
RUN mkdir -p libelf
RUN tar -xzf lb.tar.gz -C libelf --strip-components 1
WORKDIR /libelf
RUN ./configure 
RUN make -j8
RUN make install

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_vita_imports_stub_new.cpp -fsanitize=fuzzer,address -L /repo/build/src/ -lvita-import -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libyaml-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_vita_imports_stub_new
