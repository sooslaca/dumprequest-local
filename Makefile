.PHONY: all build

DHTTP_PROXY = $(or ${HTTP_PROXY},${http_proxy},${ALL_PROXY},${all_proxy},"")
DHTTPS_PROXY = $(or ${HTTPS_PROXY},${https_proxy},${ALL_PROXY},${all_proxy},"")
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

all: build

build:
	@echo ==== DOCKER BUILD
	docker build --progress=plain --no-cache -t sooslaca/dumprequest .
