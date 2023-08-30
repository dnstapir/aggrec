CONTAINER=		ghcr.io/dnstapir/aggregate-receiver:latest
CONTAINER_BASE=		aggrec:latest

all:

container:
	docker build -t $(CONTAINER) -t $(CONTAINER_BASE) .

push-container:
	docker push $(CONTAINER)

server: clients clients/test.pem
	flask --app 'aggrec.app:create_app("../example.toml")' run --debug

client: test-private.pem
	python3 tools/client.py

keys: test.pem

test-private.pem:
	openssl ecparam -genkey -name prime256v1 -noout -out $@

clients:
	mkdir clients

clients/test.pem: test-private.pem
	openssl ec -in $< -pubout -out $@
	
test:
	pytest --isort --black --pylama

lint:
	pylama .

reformat:
	isort .
	black .
	
clean:
	rm -f *.pem
	rm -fr clients

realclean: clean
	poetry env remove --all
