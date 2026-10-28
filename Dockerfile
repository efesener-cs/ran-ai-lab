FROM ubuntu:22.04 AS base
ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_JOBS=2
ARG NS3_REV=208e553148755161dc4466b30654d75c6e58832b
ARG E2SIM_REV=951b3e9e99b47260f1525d2a95fa4b2f8065530e
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git build-essential cmake ninja-build pkg-config \
    python3 python3-pip libeigen3-dev libgsl-dev libsqlite3-dev libxml2-dev \
    libsctp-dev lksctp-tools autoconf automake libtool bison flex \
    && rm -rf /var/lib/apt/lists/*
COPY docker/requirements.txt /opt/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /opt/requirements.txt \
    && python3 -m pip freeze > /opt/python-packages.txt
ENV MPLBACKEND=Agg PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/ran-ai-lab
ENTRYPOINT ["python3"]
CMD ["-m", "unittest", "discover", "-p", "test_*.py"]

FROM base AS native
ARG BUILD_JOBS=2
ARG NS3_REV=208e553148755161dc4466b30654d75c6e58832b
ARG E2SIM_REV=951b3e9e99b47260f1525d2a95fa4b2f8065530e
RUN git clone https://github.com/wineslab/o-ran-e2sim.git /opt/e2sim \
    && git -C /opt/e2sim checkout --detach "$E2SIM_REV" \
    && cmake -S /opt/e2sim/e2sim -B /opt/e2sim/build -DDEV_PKG=1 -DLOG_LEVEL=2 \
    && cmake --build /opt/e2sim/build -j "$BUILD_JOBS" \
    && cmake --install /opt/e2sim/build && ldconfig \
    && test -f /usr/local/include/e2sim/e2sim.hpp
RUN git clone https://github.com/efesener-cs/ns-o-ran-ns3-mmwave.git /opt/ns-o-ran-ns3-mmwave \
    && git -C /opt/ns-o-ran-ns3-mmwave checkout --detach "$NS3_REV" \
    && cd /opt/ns-o-ran-ns3-mmwave \
    && USER=builder ./ns3 configure --disable-python-bindings --disable-examples --disable-gtk \
    && USER=builder ./ns3 build -j "$BUILD_JOBS"
COPY . .
RUN python3 build_offline.py \
    && printf 'ns3=%s\ne2sim=%s\n' "$NS3_REV" "$E2SIM_REV" > /opt/dependency-revisions.txt

FROM base AS live
ARG BUILD_JOBS=2
ARG NS3_REV=3b4c4f10d46129ba2e8ca382374459ba27051fdb
ARG E2SIM_REV=732d64703bb7f4ba585c434a133cf4cf23972298
ARG FLEXRIC_REV=46af1074d3580eed515fb84a88099c099e15b6e4
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-12 g++-12 nlohmann-json3-dev libpcre2-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
ENV CC=gcc-12 CXX=g++-12 RAN_AI_IN_CONTAINER=1
RUN git clone https://github.com/MinaYonan123/e2sim-kpmv3.git /opt/e2sim \
    && git -C /opt/e2sim checkout --detach "$E2SIM_REV" \
    && cmake -S /opt/e2sim/e2sim -B /opt/e2sim/build -DDEV_PKG=1 -DLOG_LEVEL=2 \
    && cmake --build /opt/e2sim/build -j "$BUILD_JOBS" \
    && cmake --install /opt/e2sim/build && ldconfig
RUN git clone https://github.com/MinaYonan123/mmwave-LENA-oran.git /opt/mmwave-LENA-oran \
    && git -C /opt/mmwave-LENA-oran checkout --detach "$NS3_REV" \
    && git -C /opt/mmwave-LENA-oran submodule update --init --recursive \
    && cd /opt/mmwave-LENA-oran \
    && USER=builder ./ns3 configure --disable-python-bindings --disable-examples \
    && USER=builder ./ns3 build -j "$BUILD_JOBS"
RUN git clone https://gitlab.eurecom.fr/mosaic5g/flexric.git /opt/flexric \
    && git -C /opt/flexric checkout --detach "$FLEXRIC_REV"
COPY . .
# Configure with the same KPM-only wrapper used for each isolated run.
RUN python3 -c 'from labcore.portable_build import configure_flexric; from pathlib import Path; import sys; configure_flexric(Path("/opt/flexric"), Path("/opt/flexric/build"), sys.stdout)' \
    && printf 'ns3=%s\ne2sim=%s\nflexric=%s\n' "$NS3_REV" "$E2SIM_REV" "$FLEXRIC_REV" > /opt/dependency-revisions.txt
