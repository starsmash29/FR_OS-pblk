# Test first

The point of a failing test written *before* the change is proof: the test
can fail, it failed for the reason you meant, and your change is what made
it pass. A test written after the code often only proves the code does
what the code does.

## RED

1. Pick the test file the plan named; mirror its fixtures and style.
2. Prefer the real thing over a mock, as AGENTS.md asks: real `nft`, real
   network namespaces (`tests/test_iot_isolation.py` shows how), real Unix
   sockets. Root-only tests skip themselves without root; keep that habit.
3. Run only that test and watch it fail:
   ```bash
   python3 -m pytest tests/test_<area>.py -q -k <name>
   ```
   (webUI tests live in `tests/webui/` and run on their own.)
4. Read the failure. It must fail *because the feature is missing*, not
   because of an import error, a typo or a missing fixture. A test that was
   written but never run does not count as RED.
5. Note the command and the key line of output; it goes in the PR body.

For a bug: the RED test reproduces the bug. For a security finding: the
RED test is the attack (the bad input reaching the argv, the unprivileged
peer calling a root command) and it must currently succeed.

Good RED targets in this repo: validators and parsers (consider a
Hypothesis property test, see the vendored `property-based-testing` skill),
the generated nft script for a given config, the helper's peer policy,
systemd sandbox settings (`tests/test_systemd_sandbox.py`), and for boot
behaviour a new check in `installer/qemu-boot-test.py`.

## GREEN

Write the smallest change that makes that test pass. Then rerun the same
test and confirm it passes. Then run the area's whole test file, because a
green new test with a red neighbour is not green.

## Refactor

Only on green. Tidy names, remove duplication, add the *why* to the
docstring with the security-lessons or review ID, the way the surrounding
code does. Rerun the tests after.

## Checkpoints

If you are on the item's branch, a commit after RED (the test) and after
GREEN (the fix) makes the evidence survivable: anyone can check out the
RED commit and see it fail. Commit messages say which stage and what was
seen. Never force-push to tidy them.

## Evidence for the PR

```
RED:   python3 -m pytest tests/test_x.py -k y -q  ->  1 failed (AssertionError: ...)
GREEN: same command                                ->  1 passed
Area:  python3 -m pytest tests/test_x.py -q        ->  N passed
```
