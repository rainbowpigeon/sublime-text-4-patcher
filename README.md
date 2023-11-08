# sublime-text-4-patcher
Python 3 patcher for Sublime Text v4107-4160 Windows x64

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

### Input Prompt Mode

```python3 sublime_text_4_patcher.py```

You will then be prompted to enter the file path to `sublime_text.exe`.

### Command-Line Mode

```python3 sublime_text_4_patcher.py <path_to_sublime_text.exe>```

**IMPORTANT**: Remember to enter any text as the license key afterwards! For stable versions, you can accomplish this by going to Help > Enter License. 

## Screenshots

![Script in action](https://user-images.githubusercontent.com/16717153/147089101-ada1e8fe-e101-47f1-8548-1f7f6dfaa85d.png)
