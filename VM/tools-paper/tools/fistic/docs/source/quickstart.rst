Quick Start
===========

**Fistic** is provided as a Python module with additional scripts for basic use cases.

Requirements
------------

**Fistic** depends on Python 3 and Pip for installation.
Additionally, a qEMU installation is required to use the qEMU evaluator.
Details on how to compile for and use this evaluator are described in :ref:`qemu-evaluation`.

Installation
------------

**Suggested solution:** run :code:`./init.sh` and follow the instructions.

**Alternative solution:**

        **Fistic** is a Python 3 package and can be installed locally by running :code:`pip3 install .`.
        **Fistic** depends on the `**PulseUtils** python package <https://git-dscin.intra.cea.fr/pulse-ia/pulseutils>`
        for its functioning arm parser and various utility classes.
        A functioning **PulseUtils** version is usually submoduled in :code:`local/pulseutils` and can be installed with :code:`pip3 install local/pulseutils`.

        The **Fistic** docker container can be built from the :code:`docker/Dockerfile` dockerfile at the root directory.
        This required that all submodules are correctly initialized and updated.

Usage
-----

**Fistic** is used to perform an evaluation of a fault injection on a source armv7 binary.
It takes as input the source binary and a faulting scenario, generated mutants of the source binary according to this scenario and can additionally run the mutant programs with qemu.
It bundles a python package and three utility scripts for fault simulation and evaluation:

        - :code:`fistic-core` is used for generating mutants and evaluating them,
        - :code:`fistic-evaluate` is used for evaluating a single binary,
        - :code:`fistic-mapper` is used for creating binary instructions mappings.

Currently, **Fistic** only accepts fault scenario that target at least a full function of the source binary.
Available fault models are instruction skip, instruction replacement and payload injection.
**Fistic** can fault more that one consecutive instructions and handle mutifault scenarios, albeight with the usual exponential explosion.

Quickstart How To
-----------------

- Mutate a binary by skipping the instruction at a given address: :code:`fistic-core -b binary.elf -e none --placer address --fault-model skip -t 10000 -a address`.
- Generate mutants skipping the addresses of a given function: code:`fistic-core -b binary.elf -e none --placer function --fault-model skip -t 10000 -f function`.
- Evaluate the mutants with the qEMU evaluator: code:`fistic-core -b binary.elf -e qemu --placer function --fault-model skip -t 10000 -f function`.

Development
-----------

- Add a new fault model: subclass :class:`fistic.faulters.core.GenericFaulter`.
- Add a new fault placer: sublass :class:`fistic.placers.core.GenericPlacer`.
- Add a new evaluator: subclass :class:`fistic.evaluators.core.GenericEvaluator`.

