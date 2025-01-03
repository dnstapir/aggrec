FROM python:3.12 AS builder
RUN pip3 install poetry
WORKDIR /src
ADD . /src
RUN poetry build

FROM python:3.12
WORKDIR /tmp
COPY --from=builder /src/dist/*.whl .
RUN pip3 install *.whl && rm *.whl
RUN useradd -u 1000 -m -s /sbin/nologin aggrec
USER aggrec
ENTRYPOINT ["aggrec_server"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
