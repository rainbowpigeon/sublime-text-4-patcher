# sublime-text-4-patcher
Python 3 patcher for Sublime Text v4107-4164 Windows x64

Credits for most signatures and patching logic goes to https://github.com/leogx9r

- Uses signatures instead of hardcoded offsets
- Automatic version detection for stable/dev channels
- No host blocking needed
- Enter any text as license
- ~~Disables crash report telemetry~~
- Disables phoning home
- Minimal dependencies
- Single Python file for convenience

## Requirements

```pip3 install -r requirements.txt```

or just

```pip3 install pefile```

It's just for `pefile` which is indirectly used for version detection.

## Usage

You only need `sublime_text_4_patcher.py` from this repository (and the aforementioned requirements). 

**IMPORTANT**: Remember to enter any text as the license key after patching! For stable versions, you can accomplish this by going to Help > Enter License. 

### Input Prompt Mode

```python3 sublime_text_4_patcher.py```

You will then be prompted in the console to enter the file path to `sublime_text.exe`.

### Command-Line Mode

```python3 sublime_text_4_patcher.py <path_to_sublime_text.exe>```

### Test Mode

```python3 sublime_text_4_patcher.py -t <directory_with_sublime_text_build_*_x64.zips>```

The script will extract `sublime_text.exe` from each ZIP file into its own folder and try to patch it. Results are collated and logged to console.

### Help

```
C:\>py sublime_text_4_patcher.py -h
usage: sublime_text_4_patcher.py [-h] [-t DIRPATH] [-f {stable,dev}] [filepath]

Sublime Text v4107-4164 Windows x64 Patcher by rainbowpigeon

positional arguments:
  filepath              File path to sublime_text.exe

options:
  -h, --help            show this help message and exit
  -t DIRPATH, --test DIRPATH
                        Directory path containing sublime_text_build_*_x64.zip files for batch testing
  -f {stable,dev}, --force {stable,dev}
                        Force patching even if detected Sublime Text version does not exist in the patch database

Report any issues at github.com/rainbowpigeon/sublime-text-4-patcher/issues!
```

## Screenshots

![Script in action](https://user-images.githubusercontent.com/16717153/147089101-ada1e8fe-e101-47f1-8548-1f7f6dfaa85d.png)
