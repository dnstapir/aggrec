CONTAINER=		ghcr.io/dnstapir/aggrec:latest
CONTAINER_BASE=		aggrec:latest
BUILDINFO=		aggrec/buildinfo.py

DEPENDS=		$(BUILDINFO)


all: $(DEPENDS)

$(BUILDINFO):
	printf "__commit__ = \"`git rev-parse HEAD`\"\n__timestamp__ = \"`date +'%Y-%m-%d %H:%M:%S %Z'`\"\n" > $(BUILDINFO)	

container: $(DEPENDS)
	docker buildx build -t $(CONTAINER) -t $(CONTAINER_BASE) .

push-container:
	docker push $(CONTAINER)

server: $(DEPENDS) clients clients/test.pem
	poetry run aggrec_server --config example.toml --host 127.0.0.1 --port 8080 --debug

client: $(DEPENDS) test-private.pem
	python3 tools/client.py

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
	poetry run pytest --isort --black --pylama

lint:
	poetry run pylama

reformat:
	poetry run isort .
	poetry run black .
	
clean:
	rm -f *.pem
	rm -fr clients
	rm -f $(BUILDINFO)

realclean: clean
	poetry env remove --all
