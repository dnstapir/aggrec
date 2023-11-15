FROM python:3.11 AS builder
RUN pip3 install poetry
WORKDIR /src
ADD . /src
RUN poetry build

FROM python:3.11
WORKDIR /tmp
COPY --from=builder /src/dist/*.whl .
RUN pip3 install *.whl && rm *.whl
ENTRYPOINT aggrec_server
