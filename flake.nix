{
  outputs = { self, nixpkgs, ... }: let
    inherit (nixpkgs) lib;

    eachSystem = lib.genAttrs [ "riscv64-linux" "aarch64-linux" "x86_64-linux" ];
  in {
    packages = eachSystem (system: let pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.callPackage ({
        lib,
        stdenv,
        pkg-config,
        mpv-unwrapped,
        dbus,
        rtkit,
      }:

      stdenv.mkDerivation {
        __structuredAttrs = true;

        pname = "mpv-rtkit";
        version = "0";

        src = ./.;

        strictDeps = true;
        nativeBuildInputs = [ pkg-config ];
        buildInputs = [ mpv-unwrapped dbus ];

        installFlags = [ "PREFIX=${placeholder "out"}" ];
        stripDebugList = [ "share/mpv/scripts" ];

        passthru.scriptName = "rtkit.so";

        meta = {
          description = "RealtimeKit plugin for mpv";
          homepage = "https://woof.rip/mikael/mpv-rtkit";
          license = lib.licenses.eupl12;
          platforms = lib.platforms.linux;
          maintainers = with lib.maintainers; [ mvs ];
        };
      }) { };

      mpv = pkgs.mpv-unwrapped.wrapper {
        mpv = pkgs.mpv-unwrapped;
        scripts = [ self.packages.${system}.default ];
      };
    });

    devShells = eachSystem (system: {
      default = nixpkgs.legacyPackages.${system}.mkShell {
        inputsFrom = [ self.packages.${system}.default ];
      };
    });
  };
}
