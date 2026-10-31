# Candidate extractor for a controlled compatibility experiment, not yet a
# production-approved replacement for the CIC-IDS2017 feature generator.
FROM maven:3.9.9-eclipse-temurin-8@sha256:e20e4fc05fb5480c884a1f750c362ed0e91aca15cec5736e12796713710ec9b3 AS build

ARG CICFLOWMETER_COMMIT=98a5ebad0df579cc8b43eedd3421b3ae87699901
ENV GRADLE_OPTS="-Dorg.gradle.daemon=false -Xmx768m"
RUN apt-get update \
    && apt-get install -y --no-install-recommends git libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN git init . \
    && git remote add origin https://github.com/ahlashkari/CICFlowMeter.git \
    && git fetch --depth 1 origin "${CICFLOWMETER_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${CICFLOWMETER_COMMIT}"
RUN mvn -B org.apache.maven.plugins:maven-install-plugin:3.1.4:install-file \
      -Dfile=jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
      -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
RUN chmod +x gradlew \
    && ./gradlew --no-daemon --console plain installDist

FROM eclipse-temurin:8-jre-jammy@sha256:49b31e882495abeb1118de417ee696bdc929d2de238730920f1468025fc393a4
ARG CICFLOWMETER_COMMIT=98a5ebad0df579cc8b43eedd3421b3ae87699901
LABEL org.opencontainers.image.source="https://github.com/ahlashkari/CICFlowMeter" \
      org.opencontainers.image.revision="${CICFLOWMETER_COMMIT}" \
      tcc.purpose="offline-extractor-compatibility-experiment"
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/local/lib/libpcap.so \
    && mkdir -p /work && chown 10001:10001 /work
COPY --from=build /build/build/install/CICFlowMeter/ /opt/cfm/
USER 10001:10001
WORKDIR /work
ENV TZ=UTC
ENV LD_LIBRARY_PATH=/opt/cfm/lib/native:/usr/local/lib
ENTRYPOINT ["java", "-Xmx512m", "-Djava.io.tmpdir=/tmp", "-Djava.awt.headless=true", "-Djava.library.path=/opt/cfm/lib/native", "-cp", "/opt/cfm/lib/*", "cic.cs.unb.ca.ifm.Cmd"]
