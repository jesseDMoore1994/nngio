{
  description = "nngio";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    utils.url = "github:numtide/flake-utils";
    # You can add c libraries here, or use the ones from nixpkgs.
     mbedtls.url = "github:jesseDMoore1994/mbedtls/nix3.6.3";
     nng.url = "github:jesseDMoore1994/nng/nix1.11";
    # libauthorized-keys.url = "github:jesseDMoore1994/libauthorized_keys";
  };

  outputs = { 
    self,
    nixpkgs,
    mbedtls,
    nng,
    # libauthorized-keys,
    ... 
  }@inputs: inputs.utils.lib.eachSystem [
    "x86_64-linux" "i686-linux" "aarch64-linux" "x86_64-darwin"
  ] (system: 
  let 
      mbedtls_out = mbedtls.defaultPackage.${system}.out;
      nng_out = nng.defaultPackage.${system}.out;
      #libauthorized-keys_out = libauthorized-keys.defaultPackage.${system}.out;
      pkgs = import nixpkgs {
        inherit system;
      };
      version = "0.1.0";
      package_name = "nngio";
      deps = [
        pkgs.clang
        pkgs.valgrind
        nng_out
        mbedtls_out
        #libauthorized-keys_out
      ];
      production = pkgs.stdenv.mkDerivation {
        pname = "${package_name}";
        version = version;
        src = ./.;
        nativeBuildInputs = deps;
        buildPhase = ''
          make test
        '';
        installPhase = ''
          OUTPUT_DIR=$out make $out
        '';
      };
      debug = pkgs.stdenv.mkDerivation {
        pname = "${package_name}-debug";
        version = version;
        src = ./.;
        nativeBuildInputs = deps;
        buildPhase = ''
          DEBUG=1 make test
        '';
        installPhase = ''
          OUTPUT_DIR=$out make $out
        '';
      };
  in rec {
    defaultApp = inputs.utils.lib.mkApp { drv = defaultPackage; };
    defaultPackage = production;
    debugPackage = debug;
    devShell = pkgs.mkShell {
      buildInputs = deps ++ [pkgs.gdb];
      shellHook = ''
          export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${defaultPackage.out}/lib"
          export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${mbedtls_out}/lib"
          export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${nng_out}/lib"
      ''; # Add any additional library paths above like this:
          # export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${libauthorized-keys_out}/lib"
    };
  });
}
