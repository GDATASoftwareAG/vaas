############################################################
# Just (https://github.com/casey/just) commands for
# building, testing and releasing the Verdict-as-a-Service 
# libraries project.
#
# You can switch into a development shell with all the
# necessary dependencies by running `nix develop`.
# 
# Commands can be listed with `just --list` and run with
# `just <command>`.
############################################################


############################################################
# General commands & variables
############################################################

version := "0.0.0"

# Copies a `.env.https` or `.env.wss` file from the root directory to all 
# language directories. The `.env.https` file is used for the HTTP API (most SDKs), 
# while the `.env.wss` file is used for the WebSocket API.
populate-env: populate-cpp-env \
  populate-rust-env \
  populate-ts-env \
  populate-dotnet-env \
  populate-go-env \
  populate-python-env \
  populate-php-env \
  populate-java-env \
  populate-shell-env

populate-cpp-env:
  mkdir -p cpp/build && cp .env.https cpp/build/.env

populate-rust-env:
  cp .env.https rust/.env

populate-ts-env:
  cp .env.wss typescript/.env

populate-dotnet-env:
  cp .env.https dotnet/.env

populate-go-env:
	cp .env.https golang/vaas/v3/.env
	cp .env.https golang/vaas/v3/examples/file-verdict-request/.env
	cp .env.https golang/vaas/v3/examples/vaasctl/.env
	cp .env.https golang/vaas/v3/pkg/vaas/.env
	cp .env.https golang/vaas/v3/pkg/authenticator/.env

populate-python-env:
  cp .env.https python/.env

populate-php-env:
  cp .env.https php/tests/VaasTesting/.env

populate-java-env:
  cp .env.https java/.env

populate-shell-env:
  cp .env.https shell/.env

############################################################
# Commands for all languages at once.
############################################################

build-all: build-rust build-ts build-dotnet build-go build-java build-cpp

test-all: test-rust test-ts test-dotnet test-go test-python test-php test-java test-cpp

clean-all: clean-rust clean-ts clean-dotnet clean-go clean-python clean-php clean-java clean-cpp

############################################################
# Rust commands
############################################################

build-rust:
	cd rust && cargo build && cd -

test-rust:
	cd rust && cargo test --all && cd -

clean-rust:
	cd rust && cargo clean && cd -

release-rust:
	git tag -a rs{{version}} -m "Release Rust SDK {{version}}" && git push origin rs{{version}}


############################################################
# TypeScript commands
############################################################

install-ts:
	cd typescript && npm install && cd -

build-ts: install-ts
	cd typescript && npm run build && cd -

test-ts: install-ts
	cd typescript && npm run test && cd -

clean-ts:
	cd typescript && rm -rf node_modules && cd -

release-ts:
	git tag -a ts{{version}} -m "Release TypeScript SDK {{version}}" && git push origin ts{{version}}


############################################################
# .NET commands
############################################################

build-dotnet:
	cd dotnet/Vaas && dotnet build && cd -

test-dotnet:
	cd dotnet/Vaas && dotnet test && cd -

clean-dotnet:
	cd dotnet/Vaas && dotnet clean && cd -

release-dotnet:
	git tag -a cs{{version}} -m "Release .NET SDK {{version}}" && git push origin cs{{version}}


############################################################
# Go commands
############################################################

install-go:
	cd golang/vaas/v3 && go mod download && cd -

build-go: install-go
	cd golang/vaas/v3 && go build ./... && cd -

test-go: build-go
	cd golang/vaas/v3 && go test -race ./... && cd -

clean-go:
	cd golang/vaas/v3 && go clean ./... && cd -

release-go:
	git tag -a golang/vaas/v{{version}} -m "Release Go SDK {{version}}" && git push origin golang/vaas/v{{version}}


############################################################
# Python commands
############################################################

virtualenv-python:
	cd python && python3 -m venv venv && cd -

install-python: virtualenv-python
	cd python && source venv/bin/activate && pip3 install . && pip3 install -e ".[test]" && cd -

test-python: install-python
	cd python && source venv/bin/activate && pytest -v --tb=short && cd -

clean-python:
	cd python && rm -rf ./venv && cd -

release-python:
	git tag -a py{{version}} -m "Release Python SDK {{version}}" && git push origin py{{version}}


############################################################
# PHP commands
############################################################

install-php:
	cd php/tests/VaasTesting && composer install && cd -

test-php: install-php
	cd php/tests/VaasTesting && ./vendor/bin/phpunit --color --testdox --exclude-group exclude && cd -

clean-php:
	cd php/tests/VaasTesting && rm -rf vendor && cd - 

release-php:
	git tag -a php{{version}} -m "Release PHP SDK {{version}}" && git push origin php{{version}}


############################################################
# Java commands
############################################################

build-java: 
	cd java && gradle build -x test && cd -

test-java:
	cd java && gradle clean build && cd -

clean-java:
	cd java && gradle clean && cd -

release-java:
	git tag -a java{{version}} -m "Release Java SDK {{version}}" && git push origin java{{version}}


############################################################
# C++ commands
############################################################

build-cpp:
	cd cpp && cd build && cmake .. && make && cd -

test-cpp: build-cpp
	cd cpp/build && ./vaas_test --exit=true && cd -

clean-cpp:
	cd cpp && rm -rf build && cd -

release-cpp:
	git tag -a cpp{{version}} -m "Release C++ SDK {{version}}" && git push origin cpp{{version}}

############################################################
# Just aliases
############################################################

alias pa := populate-env

alias ba := build-all
alias ta := test-all
alias ca := clean-all

alias brs := build-rust
alias trs := test-rust
alias crs := clean-rust

alias bts := build-ts
alias tts := test-ts
alias cts := clean-ts

alias bdn := build-dotnet
alias tdn := test-dotnet
alias cdn := clean-dotnet

alias bgo := build-go
alias tgo := test-go
alias cgo := clean-go

alias tpy := test-python
alias cpy := clean-python

alias tph := test-php
alias cph := clean-php

alias bja := build-java
alias tja := test-java
alias cja := clean-java

alias bcp := build-cpp
alias tcp := test-cpp
alias ccp := clean-cpp
