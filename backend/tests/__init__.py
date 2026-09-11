"""Test packages.

``tests`` and ``tests.oracle`` are packages so that pytest names the oracle's
search test ``tests.oracle.test_search`` instead of ``test_search``, which is
the name ``tests/engine/test_search.py`` already occupies. The engine and the
oracle each have a search test, deliberately under the same file name, and
without this only one of the two is collected.

The other test directories are left as plain directories on purpose: they rely
on pytest putting their own directory on ``sys.path``, which is how they import
a sibling ``conftest`` by name.
"""
