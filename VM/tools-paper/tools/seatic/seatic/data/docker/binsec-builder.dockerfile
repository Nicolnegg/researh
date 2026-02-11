FROM	nixos/nix
RUN	nix-channel --add https://nixos.org/channels/nixpkgs-unstable nixpkgs
RUN	nix-channel --update
RUN	nix-env -i git unzip gosu bash niv python gnused
RUN	ln -s $(which python) /usr/bin/python
RUN	ln -s $(which sed) /usr/bin/sed
COPY	binsec-src binsec-src
COPY	unisim-src unisim-src
COPY	cav20-src/libase libase-src
WORKDIR	binsec-src
RUN	sed '2 a , gmp' nix/unisim.nix > nix/tmp.unisim.nix && sed '65 a         gmp' nix/tmp.unisim.nix > nix/unisim.nix
RUN	niv drop unisim
RUN	niv add local --name unisim --path /unisim-src
RUN	niv update unisim -a rev=198e957d3f7c64201969d5c5a646937cf266f5b4
RUN	niv drop libase
RUN	niv add local --name libase --path /libase-src
RUN	nix-build nix/pkgs.nix -A binsec_appimage --show-trace
RUN	cp result/binsec-x86_64.AppImage /
