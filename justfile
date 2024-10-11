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

# Copy a `.env` file from the root directory to all 
# language directories. For the C++ SDK, an `.cpp.env` is 
# required, as the C++ SDK needs different credentials to
# be run in the statigin environment.
# ATTENTION: The `.env` & `.cpp.env` has to be placed manually in the
# root directory, as secrets must not be checked into
# the git repository.
populate-env:
	mkdir -p cpp/build && cp .cpp.env cpp/build/.env
	cp .env rust/.env
	cp .env typescript/.env
	cp .env dotnet/.env
	cp .env python/.env
	cp .env golang/vaas/.env
	cp .env golang/vaas/v2/.env
	cp .env golang/vaas/v2/examples/file-verdict-request/.env
	cp .env golang/vaas/v2/pkg/vaas/.env
	cp .env golang/vaas/v2/pkg/authenticator/.env
	cp .env golang/vaas/pkg/authenticator/.env
	cp .env golang/vaas/pkg/vaas/.env
	cp .env java/.env
	cp .env php/tests/vaas/.env
	cp .env ruby/test/.env
	cp .env shell/.env

############################################################
# Commands for all luanguages at once.
############################################################

build-all: build-rust build-ts build-dotnet build-go build-python build-php build-java build-ruby build-cpp

test-all: test-rust test-ts test-dotnet test-go test-python test-php test-java test-ruby test-cpp

clean-all: clean-rust clean-ts clean-dotnet clean-go clean-python clean-php clean-java clean-ruby clean-cpp

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

build-go:
	cd golang/vaas/v2 && go build ./... && cd -

test-go:
	cd golang/vaas/v2 && go test -race ./... && cd -

clean-go:
	cd golang/vaas/v2 && go clean ./... && cd -

release-go:
	git tag -a golang/vaas/v{{version}} -m "Release Go SDK {{version}}" && git push origin golang/vaas/v{{version}}


############################################################
# Python commands
############################################################

virtualenv-python:
	cd python && python3 -m venv venv && cd -

install-python: virtualenv-python
	cd python && source venv/bin/activate && pip3 install -r requirements.txt && cd -

test-python: install-python
	cd python && source venv/bin/activate && python -m unittest -v tests/test_* && cd -

clean-python:
	cd python && rm -rf ./venv && cd -

release-python:
	git tag -a py{{version}} -m "Release Python SDK {{version}}" && git push origin py{{version}}


############################################################
# PHP commands
############################################################

install-php:
	cd php/tests/vaas && composer install && cd -

test-php: install-php
	cd php/tests/vaas && ./vendor/bin/phpunit --color --testdox && cd -

clean-php:
	cd php/tests/vaas && rm -rf vendor && cd - 

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
# Ruby commands
############################################################

install-ruby:
	cd ruby && gem install --dev "vaas-0.0.1.gem" && cd -

build-ruby:
	cd ruby && gem build vaas.gemspec && cd -

test-ruby: install-ruby 
	cd ruby/test && ruby vaas_test.rb && cd -

clean-ruby:
	cd ruby && gem clean && cd -

release-ruby:
	git tag -a rb{{version}} -m "Release Ruby SDK {{version}}" && git push origin rb{{version}}


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

alias brb := build-ruby
alias trb := test-ruby
alias crb := clean-ruby

alias bcp := build-cpp
alias tcp := test-cpp
alias ccp := clean-cpp
