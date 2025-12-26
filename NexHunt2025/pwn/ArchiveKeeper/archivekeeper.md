### ArchiveKeeper-Easy

##### Categories: `pwn`

**Libc leak via __libc_start_main, can also be via puts() but for a bit of variety, and basic ROP (we are given a "useless_gadget" function) to obtain a shell.**

- Protects and disassemble useless_gadget function.

   <img width="714" height="292" alt="Image" src="https://github.com/user-attachments/assets/2775e55b-09bd-4c3e-bf65-95ebb96b63c8" />

   <img width="760" height="285" alt="Image" src="https://github.com/user-attachments/assets/d458081c-9842-4764-b6cc-dc2eecf1ec3d" />

   FLAG`nexus{B0ok_F0uND_L1BC_R3t}`
