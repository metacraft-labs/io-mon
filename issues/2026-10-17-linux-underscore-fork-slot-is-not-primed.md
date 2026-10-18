# The Linux shim's `_Fork` slot is resolved lazily, so the slot-priming gate fails

|             |                                                                                                                            |
| ----------- | -------------------------------------------------------------------------------------------------------------------------- |
| Status | in-progress (nixos-ci-bare-002:fix-linux-underscore-fork-slot-is-not-primed) |
| Recorded    | 2026-10-17                                                                                                                 |
| Observed in | io-mon @ f33311e (the commit that added the slot) and @ 3f8788c, x86_64 NixOS                                              |
| Area        | `src/io_mon/hooks/linux_preload_runtime.nim`: `_Fork`, `real_underscore_fork_ptr`, `ct_linux_preload_prime_real_functions` |

## Observed

`tests/linux/test_io_mon_shim_host_allocator_isolation.nim` fails its
`t_every_real_function_slot_is_primed` case:

```
    declared slots: 98
    real_underscore_fork_ptr is not primed in ct_linux_preload_prime_real_functions
    .../tests/linux/test_io_mon_shim_host_allocator_isolation.nim(711, 12): Check failed: primed
  [FAILED] t_every_real_function_slot_is_primed
```

f33311e ("fix(linux): record or report what fork children read before
exec") added the `_Fork` interposition. Its `real_underscore_fork_ptr` slot
is filled by `ct_resolve("_Fork")` on first use, inside the hook. Every other
`real_*_ptr` slot is resolved by the constructor in
`ct_linux_preload_prime_real_functions`. The test fails identically at
f33311e and at 3f8788c, the current `agents` tip, so 3f8788c did not cause
it.

## Expected

The gate's own rationale says every `real_*_ptr` slot must be primed by the
constructor (`ct_linux_preload_prime_real_functions` and the test's header
comment). `dlsym` frees and allocates through the host's allocator. A slot
first resolved from a hook can therefore deadlock a host whose first call
of that function happens while its allocator lock is held. That is the
Chromium class cb1db14 fixed ("keep the shim off the host allocator so
Chromium launches").

## Evidence

From io-mon/:

```sh
nim c -r --threads:on tests/linux/test_io_mon_shim_host_allocator_isolation.nim
```

Run inside io-mon's dev shell, at f33311e and at 3f8788c; the failing case
and its message are the same at both.

## Suggested direction

Add a `CT_PRIME(real_underscore_fork_ptr, ct_underscore_fork_fn, "_Fork")`
line to `ct_linux_preload_prime_real_functions`. `_Fork` exists only in
glibc 2.34 and later, so the slot may stay NULL after priming; the hook
already handles that with `ENOSYS`. Keep the lazy fallback for a library
loaded before the constructor ran.

## Related

- cb1db14 added the gate and the priming list.
