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
# Rust commands
############################################################

build-rust:
	cd rust && cargo build && cd -

test-rust:
	cd rust && cargo test --all && cd -

############################################################
# Just shortcuts
############################################################

alias br := build-rust
alias tr := test-rust
