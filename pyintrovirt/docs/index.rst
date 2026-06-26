.. pyintrovirt documentation master file.

pyintrovirt
===========

Python library and tools for IntroVirt VM introspection. Requires the IntroVirt
runtime library (e.g. ``libintrovirt1``) to be installed and the generated
IntroVirt Python wheel (which provides the ``introvirt`` module).

See also the `C++ API documentation <../index.html>`_.

Quick start: system call monitor
--------------------------------

The following minimal example attaches to a domain, enables the default Windows
system-call filter, and prints each syscall as it returns. It mirrors the C++
quick start on the `main documentation page <../index.html>`_.

.. literalinclude:: _static/basic_syscallmon.py
   :language: python

Build and run (replace ``win10`` with your domain name or ID):

.. code-block:: bash

   sudo python3 basic_syscallmon.py win10

Use Ctrl+C to detach cleanly. For a full-featured syscall monitor with filtering
and JSON output, see :doc:`examples/ivsyscallmon`.

API Reference
-------------

.. toctree::
   :maxdepth: 2

   api/vmi
   api/event
   api/domain

Examples
--------

.. toctree::
   :maxdepth: 2

   examples/index
