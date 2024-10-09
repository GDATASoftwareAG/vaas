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
# language directories.
# ATTENTION: The `.env` has to be placed manually in the
# root directory, as secrets must not be checked into
# the git repository.
populate-env:
	cp .env cpp/.env
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
	cp .env php/.env
	cp .env ruby/.env
	cp .env shell/.env


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
# Just aliases
############################################################

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

alias bpy := build-python
alias tpy := test-python
alias cpy := clean-python
