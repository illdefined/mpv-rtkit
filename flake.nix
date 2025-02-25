{
  outputs = { self, nixpkgs, ... }: let
    inherit (nixpkgs) lib;

    eachSystem = lib.genAttrs [ "riscv64-linux" "aarch64-linux" "x86_64-linux" ];
  in {
    packages = eachSystem (system: {
      default = nixpkgs.legacyPackages.${system}.callPackage ({
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
    });

    devShells = eachSystem (system: {
      default = nixpkgs.legacyPackages.${system}.mkShell {
        inputsFrom = [ self.packages.${system}.default ];
      };
    });
  };
}
