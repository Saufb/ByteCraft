  # ByteCraft 

  This release adds interactive stepping, watchpoints, flags tracking, undo (single-step snapshot restore), and richer example code.


  ## Highlights (what I did)
  - Interactive step mode: run `python tool.py -f ByteCraft.asm -i` and use commands like `n` (next), `c` (continue), `u` (undo last step), `p RAX 0x10` to poke registers, and `w 0xADDR:len` to add watchpoints.
  - Watchpoints: stop execution when a watched memory region changes.
  - Flags decoding: see ZF/CF/OF/SF after each step.
  - Call trace: ByteCraft keeps a simple call trace based on `call`/`ret` mnemonics.
  - Instruction logging: save logs as JSON (`--save-json`) or CSV (`--save-csv`).
  - Memory dumps for data and stack after execution.


  ## Quick start

  ```bash
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  python tool.py -f ByteCraft.asm -i -s 200 --mem-dump 64
  ```


  ## Example commands

  - Step through interactively:
`python tool.py -f ByteCraft.asm -i`


  - Run non-interactive and save JSON log:
`python tool.py -f ByteCraft.asm --save-json runlog.json`


  - Add watchpoint from CLI:
`python tool.py -f ByteCraft.asm --watch 0x100200:8 -s 200`


  ## Safety note

  I intentionally block `syscall` opcodes by default. Only use `--allow-syscalls` if you understand the risks.


  ## License

  MIT — see LICENSE file.

