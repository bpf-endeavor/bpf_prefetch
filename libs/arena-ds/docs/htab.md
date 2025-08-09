# How to use htab.h?

**Defining Key and Values**

> in eBPF program:
By default the code assumes a key of 4 B and a value of 32 B.
You can define your own key/value structures by defining `my_key_t` and
`my_value_t` types and `HTAB_KEY_DEFINED` macro.

**Creating a htab**

> in eBPF program:

Add an Arena map and a `htab *` global variable to your eBPF program. The
variable will be your handle for accessing the map.

> in userspace program

Use `htab_init_userspace` to create and initialize hash-map in the Arena memory
and update the global variable in eBPF program (the `htab *` one).


