{
  description = "rbw - unofficial Bitwarden CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        rbw = pkgs.rustPlatform.buildRustPackage {
          pname = "rbw";
          version = "1.15.0";

          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs =
            [ pkgs.installShellFiles ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.pkg-config ];

          buildInputs = [ pkgs.bash ];

          preConfigure = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
            export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"
            export OPENSSL_LIB_DIR="${pkgs.lib.getLib pkgs.openssl}/lib"
          '';

          postInstall =
            ''
              install -Dm755 -t $out/bin bin/git-credential-rbw
            ''
            + pkgs.lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) ''
              installShellCompletion --cmd rbw \
                --bash <($out/bin/rbw gen-completions bash) \
                --fish <($out/bin/rbw gen-completions fish) \
                --nushell <($out/bin/rbw gen-completions nushell) \
                --zsh <($out/bin/rbw gen-completions zsh)
            '';

          meta = {
            description = "Unofficial command line client for Bitwarden";
            homepage = "https://github.com/doy/rbw";
            license = pkgs.lib.licenses.mit;
            mainProgram = "rbw";
          };
        };
      in
      {
        packages.default = rbw;
        checks.default = rbw;
      }
    );
}
