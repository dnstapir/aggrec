CONTAINER=		ghcr.io/dnstapir/aggrec:latest
CONTAINER_BASE=		aggrec:latest
BUILDINFO=		aggrec/buildinfo.py
OPENAPI=		aggrec-api.yaml

DEPENDS=		$(BUILDINFO)


all: $(DEPENDS)

$(BUILDINFO):
	printf "__commit__ = \"`git rev-parse HEAD`\"\n__timestamp__ = \"`date +'%Y-%m-%d %H:%M:%S %Z'`\"\n" > $(BUILDINFO)

openapi: $(OPENAPI)

$(OPENAPI): $(DEPENDS)
	poetry run python tools/export_openapi_yaml.py > $@

container: $(DEPENDS)
	docker buildx build -t $(CONTAINER) -t $(CONTAINER_BASE) .

push-container:
	docker push $(CONTAINER)

server: $(DEPENDS) clients clients/test.pem
	poetry run aggrec_server --config example.toml --host 127.0.0.1 --port 8080 --debug

keys: test.pem

test-private.pem:
	openssl ecparam -genkey -name prime256v1 -noout -out $@

test-client:
	openssl rand 1024 > random.bin
	poetry run aggrec_client \
		--http-key-id test \
		--http-key-file test-private.pem \
		random.bin

clients:
	mkdir clients

clients/test.pem: test-private.pem
	openssl ec -in $< -pubout -out $@

test: $(DEPENDS)
	poetry run pytest --ruff --ruff-format

lint:
	poetry run ruff check .

reformat:
	poetry run ruff format .

clean:
	rm -f *.pem
	rm -fr clients
	rm -f $(BUILDINFO) $(OPENAPI)

realclean: clean
	poetry env remove --all
