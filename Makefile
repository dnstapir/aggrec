CONTAINER=		ghcr.io/dnstapir/aggrec:latest
CONTAINER_BASE=		aggrec:latest
BUILDINFO=		aggrec/buildinfo.py
OPENAPI=		aggrec-api.yaml

DEPENDS=		$(BUILDINFO)

PRIVATE_KEYS=		test-private-p256.pem test-private-ed25519.pem test-private-rsa2048.pem
PUBLIC_KEYS=		clients/test-p256.pem clients/test-ed25519.pem clients/test-rsa2048.pem


all: $(DEPENDS) $(PUBLIC_KEYS)

$(BUILDINFO):
	printf "__commit__ = \"`git rev-parse HEAD`\"\n__timestamp__ = \"`date +'%Y-%m-%d %H:%M:%S %Z'`\"\n" > $(BUILDINFO)

openapi: $(OPENAPI)

$(OPENAPI): $(DEPENDS)
	uv run python tools/export_openapi_yaml.py > $@

container: $(DEPENDS)
	docker buildx build -t $(CONTAINER) -t $(CONTAINER_BASE) .

push-container:
	docker push $(CONTAINER)

server: $(DEPENDS) $(PUBLIC_KEYS)
	uv run aggrec_server --host 127.0.0.1 --port 8080 --debug

test-client: test-client-p256 test-client-ed25519 test-client-rsa2048

test-client-p256: test-private-p256.pem
	openssl rand 1024 > random-p256-1.bin
	uv run aggrec_client --http-key-id test-p256 --http-key-file $< random-p256-1.bin
	openssl rand 1024 > random-p256-2.bin
	uv run aggrec_client --http-key-id test-p256 --http-key-file $< random-p256-2.bin
	uv run aggrec_client --http-key-id test-p256 --http-key-file $< random-p256-1.bin
	uv run aggrec_client --http-key-id test-p256 --http-key-file $< random-p256-1.bin

test-client-ed25519: test-private-ed25519.pem
	openssl rand 1024 > random-ed25519.bin
	uv run aggrec_client --http-key-id test-ed25519 --http-key-file $< random-ed25519.bin

test-client-rsa2048: test-private-rsa2048.pem
	openssl rand 1024 > random-rsa2048.bin
	uv run aggrec_client --http-key-id test-rsa2048 --http-key-file $< random-rsa2048.bin

test-client-large: test-private-ed25519.pem
	openssl rand 10485760 > random-ed25519-large.bin
	uv run aggrec_client --http-key-id test-ed25519 --http-key-file $< random-ed25519-large.bin

keys: clients/test-p256.pem clients/test-ed25519.pem clients/test-rsa2048.pem

test-private-p256.pem:
	openssl ecparam -genkey -name prime256v1 -noout -out $@

test-private-rsa2048.pem:
	openssl genpkey -algorithm RSA -out $@ -pkeyopt rsa_keygen_bits:2048

test-private-ed25519.pem:
	openssl genpkey -algorithm ed25519 -out $@

clients:
	mkdir clients

clients/test-p256.pem: clients test-private-p256.pem
	openssl ec -in test-private-p256.pem -pubout -out $@

clients/test-ed25519.pem: clients test-private-ed25519.pem
	openssl pkey -in test-private-ed25519.pem -pubout -out $@

clients/test-rsa2048.pem: clients test-private-rsa2048.pem
	openssl pkey -in test-private-rsa2048.pem -pubout -out $@

test: $(DEPENDS) $(PUBLIC_KEYS)
	uv run pytest --ruff --ruff-format

coverage:
	uv run coverage run -m pytest --verbose
	uv run coverage html

lint:
	uv run ruff check .

reformat:
	uv run ruff check --select I --fix .
	uv run ruff format .

clean:
	rm -f $(PUBLIC_KEYS) $(PRIVATE_KEYS)
	rm -fr clients random*.bin
	rm -f $(BUILDINFO) $(OPENAPI)

realclean: clean
	rm -fr .venv
