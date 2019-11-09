# hal-fuzz: An HLE-based fuzzer for blob firmware

hal-fuzz is the sleeker, faster, fuzzing-oriented version of HALucinator.
It was developed as part of our paper (cictation pending).

It was also used by the Shellphish hacking team to win the 2019 CSAW Embedded Security Challenge(https://github.com/TrustworthyComputing/csaw_esc_2019 ), by leveraging its rehositng, fuzzing, and debugging capabilities.

If you're interested in re-hosting entire multi-node systems, or re-hosting firmware needing complex interactions with the outside world, you might want to try the original, found here: https://github.com/embedded-sec/halucinator 

## What is this crazy thing?

hal-fuzz is a generic emulator based on the principle of High Level Emulation (HLE), where we replace hardware-related library functions in the binary with high-level Python replacements.  While these replacements are created manually, we show (and you can experience yourself) that these high-level replacements are shockingly easy to write.  Most of them simply take arguments from the program, and do almost nothing of consequence. In fact, many do nothing at all, and are simply nop-outs.

In this fuzzing-oriented version, we replace the combo of full-system QEMU and Avatar used to create an instrumentable environment with AFL-Unicorn(https://github.com/Battelle/afl-unicorn ).
This allows us to create the instrumentation needed to implement HLE without the bulk of our previous approach.  While we tried to engineer the system such that handlers written for one work with the other, we noticed that handlers used simply for fuzzing could be much shorter (and therefore much more performant) and opted to split up the system.  This version also forgoes concepts such as the Peripheral Server from the original HALucinator for the same reasons.

In order to make hal-fuzz work at a reasonable speed, we made a number of notable optimizations:

- *Deterministic Timers*: Timers are based on block counts, not real time.  This enables deterministic fuzzing of otherwise-asynchronous code.
- *Native Handlers*: Normal AFL-Unicorn/Python suffers from performance issues when transitioning between Unicorn and its Python bindings.  Unfortunately, Unicorn also does not provide a "conditional hook"; you can hook every block in the progrma, but not a specific block.
We therefore provide a native library to enable this in a performant way, causing a massice (about 8x) speedup.
- *Interupts* and "faux-terrupts": Interrupts are a part of life in embedded.  Unfortunately, one aspect that was lost when QEMU was slimmed-down into Unicorn was the entire notion of interrupts.  We add this notion back, in the usual HLE way, using a model of the Cortex-M NVIC. This implements the entry and exit procedures described in the ISA docs well enough to run actual RTOS bits.
Many libraries out there will take from the program a callback, which is expected to be called in an Interrupt Service Routine (ISR).  Which ISR you use is hardware-dependent, however.  We'd prefer not to worry about that with HLE, so we created the new concept of "faux-terrupts", where a handler (or any Python hook) can freely enter interrupt mode with the IRQ of its chosing, and execute these callbacks, without needing hardware-specific knowledge.
As part of this, we also enable the manipulation of the ARM Cortex M status registers from Unicorn, a feature currently missing from the mainline version.

More details can be found in the paper.


## How do I use it?

### Initial setup

If you're on Ubuntu 18.04, try running ./setup.sh.  You'll need a root password (the underlying AFL-Unicorn setup script calls sudo for us).  Cross your fingers.

If all goes well, you can now use the ./hal-fuzz script to use the tool.
We provide a selection of sample scripts which execute hal-fuzz in various configurations, to work with the binaries mentioned in our paper.  See the numerous "test" scripts in the root directory. (scripts suffixed with _parallel run a full-sized parallel AFL setup, so be careful you don't break your system with excess load!)


### Getting symbols

As we mention in the paper, you need a few things in order to use this tool, the first of which is the locaiton of the libraries in the binary-under-test.  There are two ways to get this information, which are provided to the system as a yml file:

- *Dump the symbols from an ELF*:  If you're compiling a piece of firmware yourself, or are otherwise lucky enough to have symbols around, do this.  We have a nice script (dump_symbols.py) that will do this for you, creating the needed yml file. In the future, we hope to add a loader (e.g., angr's CLE loader) to automate most of this.

- *Use LibMatch*: We created our own library-matcher as part of our paper, found here: (TODO)
This tool also outputs the yml format you need. If you've got a real blob, this is the way to go.

### Configuring hal-fuzz

We use a YAML configuration file per binary to set up emulation.  In this file, you need to specify the memory map, which libraries are in use, and any ancillary options that affect emulation, such as the configuration of peripherals you'd like.

Numerous examples exist in ./tests of how to do this, but the basic layout for a typical firmware sample is:

- *include*: The include directive accepts a list of other yml files to include.  If they contain duplicate entries, they will be merged, allowing you to override settings as you desire.  We provide YAML files for each HAL (as they typically do not change) and for the basic layout of the ISA-specified memory map, which can/should be included first.  Also include here the YAML file containing the addresses from the previous step.

- *memory_map*: This is where you tell hal-fuzz how to load the binary.  Of course, since we're dealing with blobs, this information needs to be figured out first. (hint: the ``unblob`` frontent of LibMatch might help with this.) Make sure to use the "file=" attribute to load the firmware itself into memory somewhere!

- *handlers*: Wihle most of the handler configuration is simply included from a pre-existing file, if you have any firmware-specific overrides, you can put them here.  These could include things like removing the CRC from LwIP, switching error handlers from crashes to hangs, or anything your analysis could benefit from.


### Command-line options

With the emulation environment configured, now it's time to run the tool.  hal-fuzz accepts many command-line options (queried with ./hal-fuzz --help) which are described in detail here.

- *-c*: This is the required option where you specify the YAML file for your firmware.
- *-d/--debug*: This enables debug instrumentation.  Fuzzing something? *TURN THIS OFF* to massively boost your execution speed. None of the other debugging-related options will work without this on, however
- *-t/--trace-syms*: Print to the screen a trace of the called functions, as annotated by your collected symbol table.  This is extrmeely useful for rapid debugging and development of handlers, or diagnosing crashes
- *-M/--trace-memory*: Print to the screen a full memory trace.  This is *EXTREMELY SLOW* and will produce more output than you might expect, but is the best way to triage certain kinds of crashes.  You're not getting this kind of data out of your average emulator!
- *-b/--breakpoint*: Set a breakpoint, and drop into the SparklyUnicorn(tm) debugger.  See below for details. You can set furhter breakpoints after you hit the first one (TODO: Fix this)
- *input*: The final, positional argument is a file to be fed in as the "fuzz".

### Using hal-fuzz with AFL

Ready to fuzz some drones? Great! If you've followed the steps above, hal-fuzz is already ready to use with AFL.  See our examples (e.g., ./test_st_plc_parallel.sh) for examples.  The basic usage is:

./afl-fuzz -U -m none -i ./path/to/inputs -o ./path/to/outputs -- ./hal-fuzz -c ./path/to/firmware.yml @@

Note that the first time you start, AFL will probably warn you about your system settings.  Just follow its instructions and you'll be all set.

### Debugging with hal-fuzz

Found a crash? Great! You can track it down with the provided tools.

As a first step, the -d, -t,  and -M options above might be all you need -- they'll quickly tell you where in the binary the crash occured, and a quick trace of how the culprit data got there.

If you need anything beyond that, such as single-stepping through the binary, you can do this via the new SparklyUnicorn(tm) debugger. Just pass -b followed by an address, and you'll be dropped into an ipdb shell, with the binary halted.  (NOTE: at this time, Unicorn only lets us break on the first instruction in a basic block! This is the price we pay for performance)

Once your breakpoint is hit, you're left with the Unicorn object itself (uc), which has been instrumented with many new features (it's sparkly!).  

- *Stepping*: Typing "uc.step()" will single-step the binary.  Want a live stack or register view? Try "uc.step; uc.regs; uc.stack".  ipdb lets you simply repeatedly press enter to repeat the last command, giving you GDB-like convenience.

- *Registers*: Typing "uc.regs" produces a register view. You can read and write the reigsters using uc.regs.register, like "uc.regs.r0 = 0".  

- *Stack*: Similarly, uc.stack produces a stack view, annotated with points-to register information. You can expand this using uc.stack.pp(start_offset, end_offset), or slice it for the raw data, as uc.stack[-4:16]

- *Memory*: As with the stack, memory is available at uc.mem, and can be sliced to read and write the emulator's memory.

- *Breakpoints*: You can control breakpoints using add_breakpoint() and remove_breakpoint()


## TODOs / Limitations / Help Wanted / Roadmap

hal-fuzz is a research prototype.  While we feel it's extremely useful as-is, there are many rough edges to be worked on, which we look forward to addressing.

Here's an (incomplete) list:

- *Multiple architectures*: We only support M-profile ARM CPUs at this time, since that's all we had in our evaluation.  I have left TODOs in the code where things would need to be chnaged to fix this, and Unicorn itself supports a number of architectures, so there's no reason this couldn't be implemented given some time.

- *Integrate angr's archinfo and cle*: As part of the above, we should use archinfo to abstract architecture-dependent stuff.  This includes, but is not limited to: the "return" instruction, register information, calling conventions, various kinds of endness, and so on.  CLE would provide us instant support for numerous binary formats, particularly to cover the situation where you're compiling your own firmware and have more than just a blob.  Still, CLE also has support for loading blobs, even automatically, using plugins.

- *Modernize Handlers*: The way we write handlers changed a few times during hal-fuzz's development to make things easier, such as the creation of faux-terrupts, and SparklyUnicorn.  This would dramatically cut down in the ugliness of handler code, and make implementation even easier for the analyst. Using some kind of type or calling-convention information would be the ultimate in handler creation, and could allow for semi-automation of the process.

