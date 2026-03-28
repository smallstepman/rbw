{
  description = "rbw - unofficial Bitwarden CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    in
    {
      packages = nixpkgs.lib.genAttrs systems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          isLinux = pkgs.stdenv.hostPlatform.isLinux;
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "rbw";
            version = cargoToml.package.version;

            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs =
              [ pkgs.installShellFiles ]
              ++ pkgs.lib.optionals isLinux [ pkgs.pkg-config ];

            preConfigure = pkgs.lib.optionalString isLinux ''
              export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"
              export OPENSSL_LIB_DIR="${pkgs.lib.getLib pkgs.openssl}/lib"
            '';

            postInstall =
              ''
                install -Dm755 -t $out/bin bin/git-credential-rbw
                patchShebangs $out/bin/git-credential-rbw
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
        }
      );

      checks = nixpkgs.lib.genAttrs systems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = self.packages.${system}.default;
        }
      );
    };
}
