{
  description = "A flake for easy development of the multi-language Verdict-as-a-Service libraries";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs) lib;

        tools = [
          pkgs.just
          pkgs.lazygit
        ];

        rustDeps = [
          pkgs.cargo
          pkgs.rustc
          pkgs.clippy
          pkgs.rustfmt
        ] ++ lib.optional pkgs.stdenv.isDarwin [
          pkgs.darwin.apple_sdk.frameworks.Cocoa
          pkgs.libiconv
          pkgs.iconv
        ];

        typeScriptDeps = [
          pkgs.nodejs
        ];

        dotnetDeps = [
          pkgs.dotnet-sdk_8
        ];

        goDeps = [
          pkgs.go
        ];

        pythonDeps = [
          pkgs.python3
          pkgs.python312Packages.pip
        ];

        phpDeps = [
          pkgs.php
          pkgs.php83Packages.composer
        ];

        javaDeps = [
          pkgs.jdk22
          pkgs.gradle
        ];

        rubyDeps = [
          pkgs.ruby
          pkgs.git
        ];

        cppDeps = [
          pkgs.vcpkg
          pkgs.cmake
          pkgs.curl
          pkgs.jsoncpp
          pkgs.doctest
        ];

      in
      with pkgs;
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkg-config
            openssl
          ] ++ tools
          ++ rustDeps
          ++ typeScriptDeps
          ++ dotnetDeps
          ++ goDeps
          ++ pythonDeps
          ++ phpDeps
          ++ javaDeps
          ++ rubyDeps
          ++ cppDeps;

          shellHook = ''
                        	alias c=cargo
                        	alias j=just
                        	alias lg=lazygit
                                alias ll="ls -la"
                                alias lll="ls -lah"
            		'';

          DOTNET_CLI_HOME = "/tmp/nix/.dotnet";
          GOPATH = "/tmp/nix/.go";
          GOCACHE = "/tmp/nix/.gocache";
          COMPOSER_HOME = "/tmp/nix/.composer";
          GEM_HOME = "/tmp/nix/.gem";
        };
      }
    );
}
