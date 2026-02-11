.. _qemu-evaluation:

qEMU Evaluation
===============

**Fistic** provides a qEMU evaluator (:class:`fistic.evaluators.QemuEvaluator`) for evaluating
faulted binary files and decide whether the fault triggered the vulnerable behavior or not.
As both qEMU and the compilation chain used to obtain STM32 armv7 binaries are both finicky,
setting up the use of this evaluator is a bit of a pain.

The purpose of this documentation page is to ease one up succesfully achieving this.

General Concepts
----------------

The idea of the qEMU evaluator is to decide whether a fault successfully triggered a vulnerability
from an oracle that is embedded within the program, and checked by an execution emulation with qEMU.
The **Fistic** qEMU evaluator with look for magic strings in the output of the qEMU execution;
whether this is in stdout or stderr is configurable with **Fistic** options.

The qEMU evaluators looks for the following strings:
 - :code:`==VERDICT== OK` for an execution that did not trigger the vulnerability oracle
 - :code:`==VERDICT== FAIL` for an execution that triggered the vulnerability oracle

.. note::

    If both strings are present is the evaluation output, vulnerability triggering
    (:code:`==VERDICT== FAIL`) takes priority and the binary will be marked as vulnerable.

    If none of the strings are present is the evaluation output, the evaluator will return
    :code:`NoData`.

.. warning::

    Both evaluation strings take precedence over timeout triggering and program crash.
    This means that if the program emulation outputs :code:`==VERDICT== OK` but crashes
    later on, the evaluator will still consider the binary program to be valid, that is,
    not triggering a vulnerability.

Compilation and Printing for the qEMU Oracle
--------------------------------------------

In order to use the **Fistic** qEMU evaluator, the binary program should be cross-compiled for
the STM32 armv7 (git@git-dscin.intra.cea.fr:cogito/STM32qemu-tools.git).

This can be done fairly easily by linking the library with your armv7 cross-compiler.
The issue that can arise is the use of incorrect macros for printing for the qEMU emulation.
Indeed, depending of which print macro is used, qEMU may either write to stdin
(which prevents **Fistic** from recovering its output) or fail to print anything at all.

In order to have qEMU print correctly, one must print with the :code:`PRINT` macro of
the :code:`cdg-stm32-print.h` stm32-qemu header.
A reference known to produce correctly printing arm binaries is
git@git-dscin.intra.cea.fr:cogito/STM32qemu-tools.git:bfe7598.

For this setup, **Fistic** provides in its :code:`cmake` directory two cmake module that should
lead to a functionning compilation with the :code:`arm-none-eabi-gcc` cross compilator available
in the debian package manager.
Assuming :code:`STM32qemu-tools` is cloned in the source directory and the modules installed in a
:code:`cmake` subdir from the source directory, these can be loaded with the following CMake
instructions:

.. code-block:: cmake

    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
    include(arm-none-eabi)
    include(stm32-qemu)

One can then link their source code with predefined :code:`stm32` library with :code:`target_link_libraries`.
The qEMU print header can then be included in the source code with a simple :code:`#include <cdg-stm32-print.h>`.

Checking the binary with qEMU
-----------------------------

The qEMU server used by the evaluator is hard-coded in **Fistic**.
The **strongly** suggested qEMU version is 4.2.1.
Previous version are known not either fail to print or, worse, print to stdin.
One can try the behavior of a compiled binary program with the following command:
:code:`qemu-system-arm -machine lm3s6965evb -cpu cortex-m3 -nographic -monitor null -serial null -semihosting -kernel binary.elf`
where :code:`binary.elf` is the target binary.
The user should check the following to ensure that the binary will be handled correctly by the **Fistic** evaluator:

 - the command does not crash
 - the execution correctly prints the strings it should print
 - qEMU does not print to stdin, this can be checked by redirecting both stdout and stderr (:code:`>/dev/null 2>&1`)
   and verifying that nothing is printed in the terminal.

If everything works, the binary should be handled correctly by the **Fistic** evaluator.
