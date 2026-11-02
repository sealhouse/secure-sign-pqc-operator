# The sealhouse file-based catalog.
ARG OPM
FROM ${OPM}
ENTRYPOINT ["/bin/opm"]
CMD ["serve", "/configs", "--cache-dir=/tmp/cache"]
COPY configs /configs
RUN ["/bin/opm", "serve", "/configs", "--cache-dir=/tmp/cache", "--cache-only"]
LABEL operators.operatorframework.io.index.configs.v1=/configs
