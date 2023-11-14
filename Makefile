CONTAINER=		ghcr.io/dnstapir/aggregate-receiver:latest
CONTAINER_BASE=		aggrec:latest

all:

container:
	docker build -t $(CONTAINER) -t $(CONTAINER_BASE) .

push-container:
	docker push $(CONTAINER)

server: clients clients/test.pem
	poetry run aggrec_server --config example.toml --host 127.0.0.1 --port 8080 --debug

client: test-private.pem
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
	
test:
	poetry run pytest --isort --black --pylama

lint:
	poetry run pylama

reformat:
	poetry run isort .
	poetry run black .
	
clean:
	rm -f *.pem
	rm -fr clients

realclean: clean
	poetry env remove --all
