FROM	appimagecrafters/appimage-builder:latest
RUN	apt-get update
RUN	DEBIAN_FRONTEND=noninteractive apt-get install -y bash imagemagick
RUN	mkdir -p AppDir/usr/share/icons/64x64
RUN	convert -size 64x64 xc:skyblue -fill black /AppDir/usr/share/icons/64x64/white-square.png
COPY	qemu.recipe.yml recipe.yml
RUN	appimage-builder --recipe recipe.yml
COPY	objdump.recipe.yml recipe.yml
RUN	appimage-builder --recipe recipe.yml
COPY	gcc-32.recipe.yml recipe.yml
RUN	appimage-builder --recipe recipe.yml
COPY	boolector.recipe.yml recipe.yml
RUN	appimage-builder --recipe recipe.yml
COPY	ninja.recipe.yml recipe.yml
RUN	appimage-builder --recipe recipe.yml
