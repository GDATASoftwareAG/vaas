{
  description = "A flake for easy development of the multi-language Verdict-as-a-Service librarie";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs) lib;
      in
      with pkgs;
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            just
            lazygit
          ];
        };
      }
    );
}
