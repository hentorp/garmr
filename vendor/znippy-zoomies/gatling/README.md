# rotaryengine

The shared no-barrier worker-pool engine — generic streaming gatling (split → N decode → in-order collect → sink), its fork-join sibling, async-I/O variant, and the zero-allocation chunk-revolver slot pool. Leaf crate: depends on no codec, so every codec + the znippy-zoomies root can share the ONE engine without a dependency cycle.

Part of the [nordisk](https://codeberg.org/nordisk) constellation.
