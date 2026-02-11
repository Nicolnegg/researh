#!/usr/bin/env bash

func_gitinit () {
	echo ">> updating git submodules..."
	git submodule sync --recursive || exit 1
	git submodule update --init --recursive || exit 1
}

func_docker_build () {
	echo ">> building/updating docker fistic container..."
	docker build --tag fistic --file docker/Dockerfile . || exit 1
}

func_install () {
	echo ">> installing fistic locally..." || exit 1
	pip3 install local/pulseutils . || exit 1
}

func_runtests_docker () {
	echo ">> run fistic tests in container..."
	docker run -v "$(pwd)":/homedir --user $(id -u):$(id -g) fistic pytest || exit 1
}

func_runtests_local () {
	echo ">> run fistic tests..."
	pytest || exit 1
}

func_build_doc () {
	echo ">> building documentation..."
	cd docs && make html && cd ..
}

func_docker_start () {
	echo ">> switching to docker container..."
	exec docker run --rm -it -v "$(pwd)":/homedir --user $(id -u):$(id -g) fistic bash
}

func_cleanup () {
	echo ">> cleaning up..."
	rm -rf .fistic summary.org
}

func_action_parse () {
	case $1 in
		"git")
			func_gitinit
			;;
		"dockerbuild")
			func_docker_build
                        ;;
		"dockertest")
			func_runtests_docker
			;;
		"install")
			func_install
			;;
		"test")
			func_runtests_local
			;;
		"docs")
			func_build_doc
			;;
		"clean")
			func_cleanup
			;;
		"docker")
			func_docker_start
			;;
		*)
			echo "E> unknown action: $1!"
			;;
	esac
}

func_iterate_args () {
	echo ">> executing actions..."
	for action in $@
	do
		func_action_parse $action
	done
}

func_input_action () {
	while true
	do
		read -p "?> $1? (y/n): " yn
		case $yn in
			[yY])
				$2
				break
				;;
			[nN])
				break
				;;
			*)
				echo "y/n"
				;;
		esac
	done
}

# Init Script

echo "===[ fistic init script ]==="

if [ $# -eq 0 ]
then
	echo ">> no action provided, starting interactive mode..."
	func_input_action "initialize git submodule" func_gitinit
	func_input_action "build docker container" func_docker_build
	func_input_action "install fistic" func_install
	func_input_action "build fistic documentation" func_build_doc
	echo ">> done."
	echo "============================"
else
	func_iterate_args $@
fi
