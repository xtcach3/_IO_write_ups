### GhostNotes-Easy

##### Categories: `pwn`

 The challenge is a simple heap note. The binary uses glibc 2.31, so it has tcache.

 The vulnerable function is **delete_note()**. It frees a chunk and does not set it to NULL. Now we have an UAF
 
```c
  if (((iVar2 < 0) || (9 < iVar2)) || (*(long *)(notes + (long)iVar2 * 8) == 0)) {
    puts("Invalid index or empty.");
  }
  else {
    free(*(void **)(notes + (long)iVar2 * 8));
    puts("Note deleted.");
  }
```

The **edit_note()** function is our UAF Write and **show_notes()** our UAF Read

We will use UAF Read to leak the fd pointer of a large chunk in the unsorted bin (libc leak) and then use UAF Write to perform tcache poisoning to obtain a shell

#### Checksec
```
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

<img width="430" height="212" alt="Image" src="https://github.com/user-attachments/assets/abfd8d4d-1b49-419b-b040-b1f98dd37046" />

FLAG:`nexus{h3ap_u4f_t0_tcache_p0is0ning_is_fun}`
