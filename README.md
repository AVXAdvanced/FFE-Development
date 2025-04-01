# Welcome to the FFE-Development GitHub!

## Introduction

The FFE-Development GitHub is a place where you can check out some In-Development version of FFE.

You'll need to compile these versions into an .exe file yourself, or just run them
as a .py file, if you have Python installed on your computer.

The FFE-Development GitHub is also used by me to sync my code across devices,
but you can check those versions out too.

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

## Release Naming

FFE Releases uploaded here have a certain "codename" appended to the filename, which mean different things.

Example:

"ffe_03312025_201_lyra"

Here you can see what they mean.

### LYNA

My latest successfully compiled FFE release, used for me to 
share FFE code across devices.

All LYNA releases are appended with either "LYRA or LYEE".
Find out what they mean below.

Example:

"ffe_03312025_201_lyna_lyra"

### LYRA

The latest GUI release for FFE,
featuring a Graphical User Interface.

### LYEE

The latest TUI release for FFE,
featuring a Text-Based User Interface.

**Thanks for Visiting the FFE-Development GitHub Repository.**



