A process design for the robustness evaluation of binary programs in presence of fault injections

## Dependencies:

```sh
unisim-armsec
binsec
fistic (w/ qemu-arm and arg-none-gcc)
```

## Install:

```sh
pip install .
```

## Portable:

```sh
pip install colorama pyyaml tqdm jinja2 matplotlib scipy
cp bin/seatic ./seatic.py
./seatic.py
```

## Usage (mutation, binsec, successful attack detections)

```sh
seatic -c context.yml
```

## Generate external tools appimages:
```sh
seatic -r generate-tools
```
(Note that an access to the tools repositories and docker are required)

## Legacy docker usage

```sh
docker build --tag seatic --file docker/Dockerfile .
docker run -it --rm --volume "$(pwd)":/homedir --env LOCAL_USER_ID=$(id -u) seatic seatic -c context.yml
```
