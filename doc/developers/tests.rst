Tests
=====

Test harness
------------

The test harness is a set of convenience functions used to ease testing of ``bpfilter``.

Test
~~~~
.. doxygenfile:: test.h

Symbols
~~~~~~~
.. doxygenfile:: sym.h

Mocks
~~~~~
.. doxygenfile:: mock.h

Process
~~~~~~~
.. doxygenfile:: process.h

Daemon
~~~~~~~
.. doxygenfile:: daemon.h

Filters
~~~~~~~
.. doxygenfile:: filters.h

Program
~~~~~~~
.. doxygenfile:: prog.h


Unit tests
----------

.. warning::

    In progress.


End-to-end tests
----------------

End-to-end tests are designed to validate the bytecode generated by ``bpfilter`` through the following workflow:

- Start the ``bpfilter`` daemon.
- Send a chain to the daemon to be translated into a BPF program.
- Use ``BPF_PROG_TEST_RUN`` with a dummy packet and validate the program's return code.

Run end-to-end tests with ``make e2e``. ``root`` privileges are required to start the daemon and call ``bpf(BPF_PROG_TEST_RUN)``.

The test packets are generated using a Python script and Scapy: the scripts creates ``packets.h`` which is included in the end-to-end tests sources. See ``tests/e2e/genpkts.py``.

**Adding a new end-to-end test**

End-to-end tests are defined in ``tests/e2e`` and use ``cmocka`` as the testing library. To add a new end-to-end test:

1. Add a new ``cmocka`` test in a source file under ``tests/e2e``.
2. Create a chain: use the primitives in :ref:`Filters` to easily create chains, rules, and matchers. Remember to set the ``attach=no`` option on the chain to avoid blocking your host's traffic!
3. Send the chain to the daemon. The ``e2e`` ``main()`` function should create a new instance of the daemon for each test group, so you don't have to do it yourself. Use :c:func:`bf_cli_set_chain` to send the chain to the daemon.
4. Get the file descriptor of the generated BPF program as a :c:struct:`bf_test_prog`. Use :c:func:`bf_test_prog_get` to avoid the boilerplate of creating the :c:struct:`bf_test_prog` object, allocating it, and opening the file descriptor. The BPF program identified by its name, which you control through the hook attribute ``name``.
5. Send a dummy packet to your program and validate the return value with :c:func:`bf_test_prog_run`.

**Example**

The example below will create an empty chain with a default ``ACCEPT`` policy. We expect the generated XDP program to return ``XDP_PASS`` (which is ``2``).

.. code-block:: c

    Test(xdp, default_policy)
    {
        _cleanup_bf_chain_ struct bf_chain *chain = bf_chain_get(
            BF_HOOK_XDP,
            bf_hook_opts_get(
                BF_HOOK_OPT_IFINDEX, 2,
                BF_HOOK_OPT_NAME, "bf_e2e_testprog",
                BF_HOOK_OPT_ATTACH, false,
                -1
            ),
            BF_VERDICT_ACCEPT,
            NULL,
            (struct bf_rule *[]) {
                NULL,
            }
        );
        _free_bf_test_prog_ struct bf_test_prog *prog = NULL;

        if (bf_cli_set_chain(chain) < 0)
            bf_test_fail("failed to send the chain to the daemon");

        assert_non_null(prog = bf_test_prog_get("bf_e2e_testprog"));
        assert_success(bf_test_prog_run(prog, 2, &pkt_local_ip6_tcp));
    }


Benchmarking
------------

.. warning::

    In progress.
