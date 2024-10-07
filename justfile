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
# language directories
populate-env:
	cp .env cpp/.env
	cp .env rust/.env
	cp .env typescript/.env
	cp .env dotnet/.env
	cp .env python/.env
	cp .env golang/vaas/.env
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
	cd rust && git tag -a rs{{version}} -m "Release Rust SDK {{version}}" && git push origin rs{{version}} && cd -


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
	cd typescript && git tag -a ts{{version}} -m "Release TypeScript SDK {{version}}" && git push origin ts{{version}} && cd -


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
	cd dotnet/Vaas && git tag -a cs{{version}} -m "Release .NET SDK {{version}}" && git push origin cs{{version}} && cd -


############################################################
# Just aliases
############################################################

alias br := build-rust
alias tr := test-rust
alias cr := clean-rust

alias bt := build-ts
alias tt := test-ts
alias ct := clean-ts

alias bd := build-dotnet
alias td := test-dotnet
alias cd := clean-dotnet

