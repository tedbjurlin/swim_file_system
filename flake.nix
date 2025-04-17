{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    naersk,
    ...
  }:
  flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {inherit system ;};

      naersk' = pkgs.callPackage naersk {};

    in {
      defaultPackage = naersk'.buildPackage {
        src = ./.;
      };
      devShell = pkgs.mkShell {
        name = "Operating Systems";
        nativeBuildInputs = with pkgs; [
          rustc
          cargo
          rustfmt
          lldb
        ];
        RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
        packages = with pkgs; [
          just
          (python312.withPackages (python312-pkgs: [
            python312Packages.locust
          ]))
        ];
      };
    });
}
