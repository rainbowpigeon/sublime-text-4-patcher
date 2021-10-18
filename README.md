# sublime-text-4-patcher
Python 3 patcher for Sublime Text v4107-4118 Windows x64

Credits for signatures and patching logic goes to https://github.com/leogx9r

- Uses signatures instead of hardcoded offsets
- Automatic version detection for stable/dev channels (4107-4118)
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

![image](https://user-images.githubusercontent.com/16717153/137697096-7324ac5d-f513-42fb-8364-84faf1efd757.png)


