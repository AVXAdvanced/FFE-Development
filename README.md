# Welcome to the FFE-Development GitHub!

![ffe_gh_dev_banner_v3_usableres](https://drive.google.com/uc?export=view&id=1B8kgW3-AOU5fDS_8X8DFFqxdcHxpQ3mi)

## Introduction

This repository is intended to store loose FFE files, such as Beta Builds, Internal Builds, 
and old files.

Note that files here are in either the ".py" or the ".pyw" format. Both of these require you to have a recent
version of python installed. The difference between ".py" and ".pyw" is that a normal ".py" file will always
spawn a Command-Line Window, while a ".pyw" file will not. Note, you can run LYNA and LYRA builds as ".py" AND ".pyw" (use ".py" for debugging),
though Legacy (LYEE) builds can only reliably run in a ".py" file as they are Command-Line Based (TUI).

Further down in this document there are instructions on how to compile ".py" files into ".exe" (Windows Executable) Files.


## Warnings

- Not everything in these releases of FFE will work.
- You may experience UI issues
- Your files may be lost
- Some buttons may not respond.
- Spelling or Version Numbers may be incorrect.
- These Versions may not have a Build and/or Version Number

## Compiling

### Requirements

- Very Basic Understanding of the Terminal
- Very Basic Understanding of a Computer
- A Windows Computer
- Python 3.13 or greater

**1. "Download" the code**

Click on the file you want to compile, and press "Download raw file" (a small download icon in the top bar under the bar that says something like: "AVXAdvanced Update FFE.py"
You should now have a ".py" file in your downloads folder. If you do, continue to the next step.

**2. Compile!**

Open a Command Prompt Window, and type this:

"pyinstaller --onefile [DRAG YOUR .PY FILE HERE FROM EXPLORER]"

After you've done so it should look something like this:

"pyinstaller --onefile "C:\Users\[Your Username]\Downloads\FFE.py""

Note that the file path SHOULD have parenthesis (") around it for this to work properly.
Once you have this, hit ENTER.

You should see a ton of text in the Command Prompt, if yes, good.
Once it's done, head to this location:

"C:\Users\[Your Username]\dist\"

There you should find a file with the same name as the one you inputted, just with ".exe" at the end of it (if you have file extensions turned on).

**DONE!**

## Navigating the Repository

As you may have noticed, there are a few folders and files in this repository. Here's how to find what you need. 

### Files in Root

Files in Root refers to files in the root (or top-level) directory of the repository.

The builds located in root are usually currently relevant, like several betas of the same upcoming release for example.
That might look something like this:

"ffe_101725_300_01_lyra" - Referring to Beta 1 of Version 300 (aka 3.0.0) built on 101725 (aka 10/17/2025, or the 17th of October 2025).
"ffe_101925_300_02_lyra" - Referring to Beta 2 of Version 300 (aka 3.0.0) built on 101925 (aka 10/19/2025, or the 19th of October 2025).
"ffe_102025_300_03_lyra" - Referring to Beta 3 of Version 300 (aka 3.0.0) built on 102025 (aka 10/20/2025, or the 20th of October 2025).

Note, files in root may NOT be the newest, though they usually are. They include currently RELEVANT files which are mostly
new builds, but maybe also other (older) builds that were rediscovered for example.

### LYRA Builds

These are any older or currently irrelevant builds relating to FFE "LYRA", aka the official GUI versions (2.0.0 -> Current).
The naming of these builds is the same as for the root files discussed above.

### LYNA/Aetherion Builds

Aetherion was an internal project I was working on a while back, trying to add new features to FFE and rebrand it as Aetherion, codename LYNA. 
These builds are quite interesting to look at, though a lot of LYNA functionality is being ported forward to modern LYRA builds.
Again, the naming is the same as the root builds.

### LYEE Builds

LYEE Builds are the OG, TUI (Terminal-Based) versions of FFE. These versions are quite old and lacking in functionality at this point,
though they can be fun to explore to see how FFE evolved over time.

Again, naming works similar to the others, though some very old builds may have slightly different naming.

### Disfunctional Builds

As the name may suggest, these are builds that either dont work at all or are severely limited in functionality. 
This may also include builds that weren't intended for public use, though have very similar or the same functionality
as their official counterpart.

For example, a custom build like the LTK (LYRA Transition Kit) may have been based off of official versions such as 1.2.0,
though the LTK shares identical functionality. It may still be placed here as it is not a release build.

Unlike the others, naming may vary. It should be generally the same, but who knows.


**Thanks for Visiting the FFE-Development GitHub Repository.**



