# sublime-text-4-patcher
Python 3 patcher for Sublime Text v4107-4126 Windows x64

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

## Screenshots

![image](https://user-images.githubusercontent.com/16717153/137697489-e8e240af-b9e8-4964-b62a-a6862524e0ef.png)


