{
  git,
  lib,
  makeWrapper,
  nodejs,
  pnpm,
  stdenv,
  ...
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "headplane";
  version = (builtins.fromJSON (builtins.readFile ../package.json)).version;
  src = ../.;

  nativeBuildInputs = [
    makeWrapper
    nodejs
    pnpm.configHook
    git
  ];

  dontCheckForBrokenSymlinks = true;

  pnpmDeps = pnpm.fetchDeps {
    inherit (finalAttrs) pname version src;
    hash = "sha256-hu3028V/EWimYB1TGn7g06kJRIpZA6cuOIjPMEc8ddw=";
  };

  buildPhase = ''
    runHook preBuild
    pnpm build
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/{bin,share/headplane}
    cp -r build $out/share/headplane/
    sed -i "s;$PWD;../..;" $out/share/headplane/build/server/index.js
    makeWrapper ${lib.getExe nodejs} $out/bin/headplane \
        --chdir $out/share/headplane \
        --add-flags $out/share/headplane/build/server/index.js
    runHook postInstall
  '';
})
