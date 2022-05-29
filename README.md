# sublime-text-4-patcher
Python 3 patcher for Sublime Text v4107-4134 Windows x64

Credits for signatures and patching logic goes to https://github.com/leogx9r

- Uses signatures instead of hardcoded offsets
- Automatic version detection for stable/dev channels
- No host blocking needed
- Enter any text as license
- Disables crash report telemetry
- Disables phoning home

## Requirements

```pip3 install -r requirements.txt```

or just

```pip3 install pefile```

It's just for `pefile` which is indirectly used for version detection.

## Usage

```python3 sublime_text_4_patcher.py```

## Screenshots

![Script in action](https://user-images.githubusercontent.com/16717153/147089101-ada1e8fe-e101-47f1-8548-1f7f6dfaa85d.png)
