{
  inputs = {
    # use release 23.05 branch of the GitHub repository as input, this is the most common input format
    nixpkgs.url = "github:NixOS/nixpkgs/release-23.05";
    flake-utils.url = "github:numtide/flake-utils";
    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    nixpkgs,
    flake-utils,
    gitignore,
    ...
  }:
    flake-utils.lib.eachDefaultSystem
    (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            sqlite
            go_1_20
            gotools
            alejandra
          ];
        };
        packages = {
          default = pkgs.buildGoModule {
            name = "bipper";
            src = gitignore.lib.gitignoreSource ./.;
            vendorSha256 = "sha256-Ulc8pkHQN8msO+yl58CVbQDOGan7ch65TSsTqDJbTTg=";
          };
        };
      }
    );
}
