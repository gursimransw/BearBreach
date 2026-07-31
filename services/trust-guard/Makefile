IMAGE_NAME := bearbreach/trust-guard
IMAGE_TAG ?= week8
CONTAINER_NAME := trust-guard
HOST_PORT ?= 8000
CONTAINER_PORT := 8000

.PHONY: test docker-build docker-run docker-run-detached docker-stop docker-logs docker-images docker-containers

test:
	go test ./...

docker-build: test
	docker build \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-t $(IMAGE_NAME):latest \
		.

docker-run:
	docker run --rm \
		--name $(CONTAINER_NAME) \
		-p $(HOST_PORT):$(CONTAINER_PORT) \
		$(IMAGE_NAME):$(IMAGE_TAG)

docker-run-detached:
	docker run --rm -d \
		--name $(CONTAINER_NAME) \
		-p $(HOST_PORT):$(CONTAINER_PORT) \
		$(IMAGE_NAME):$(IMAGE_TAG)

docker-stop:
	docker stop $(CONTAINER_NAME)

docker-logs:
	docker logs -f $(CONTAINER_NAME)

docker-images:
	docker image ls $(IMAGE_NAME)

docker-containers:
	docker ps --filter name=$(CONTAINER_NAME)