
WannaCRI
========
A (WIP) Python library by [donmai-me](https://github.com/donmai-me) for parsing, extracting, and generating Criware's various audio and video file formats.
If you're interested in reading more about USM, you can read his write-up about it [here](https://listed.to/@donmai/24921/criware-s-usm-format-part-1)

This fork Cythonizes donmai-me's implementation of the encryption/decryption of Video and Audio. This makes the process 10-50x faster.

Support
=======
This currently supports the following formats with more planned:

✅: Implemented and tested ❓: Should work but not tested ❌: Not implemented

x/y: Extract support / Create support

## USM

### Video

| Codec | Not-encrypted | Encrypted |
| ----- | ----- |-----------|
| VP9 | ✅ / ✅  | ✅ / ✅     |
| H.264 | ✅ / ✅ | ✅ / ❓     |
| Prime | ❓ / ❌ | ❓ / ❌     |

### Audio

| Codec | Not-encrypted | Encrypted |
| ----- | ----- | ----- |
| CRI HCA | ✅ / ❌ | ✅ / ❌ |

Requirements
============
This library has the following requirements:

A working FFmpeg and FFprobe installation. On Windows, you can download official ffmpeg and ffprobe binaries and place them on your path.

This project heavily uses the [ffmpeg-python](https://pypi.org/project/ffmpeg-python) wrapper. And uses [python-json-logger](https://pypi.org/project/python-json-logger) for logging.

Installation
============

`pip install git+https://github.com/logicallyanime/WannaCRI.git`

Usage
=====
If installed, there should be a command-line tool available.

```
 Usage: wannacri [OPTIONS] COMMAND [ARGS]...                                                                                               
                                                                                                                                           
 WannaCRI CLI[]


╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ extract-usm   Extracts a USM or extracts multiple USMs given a path as input.                                                           │
│ create-usm    Creates a USM.                                                                                                            │
│ probe-usm     One of the main functions in the command-line program. Probes a USM or finds multiple USMs and probes them when given a   │
│               path as input.                                                                                                            │
│ encrypt-usm   WannaCRI Encrypt USM/s                                                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

Licence
=======
This is an open-sourced application licensed under the MIT License

