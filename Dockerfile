FROM python:3.12 AS builder
RUN pip3 install poetry
WORKDIR /src
ADD . /src
RUN poetry build

FROM python:3.12
WORKDIR /tmp
COPY --from=builder /src/dist/*.whl .
RUN pip3 install *.whl && rm *.whl
RUN useradd -r -u 1000 -g root aggrec
USER aggrec
CMD ["--host", "0.0.0.0", "--port", "8080"]
ENTRYPOINT ["aggrec_server"]
