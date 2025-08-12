import logging, os, pathlib, platform, shutil, string, tempfile, random, ffmpeg

import typer
from rich.progress import Progress,SpinnerColumn, TimeElapsedColumn
from concurrent.futures import ThreadPoolExecutor, as_completed

from typing import List, Optional
from pythonjsonlogger import jsonlogger
from pathlib import Path

import wannacri
from .codec import Sofdec2Codec
from .usm import is_usm, Usm, Vp9, H264, HCA, OpMode, generate_keys

app = typer.Typer(help=
"""[bold]WannaCRI CLI[]"""
, no_args_is_help=True, add_completion=False, rich_markup_mode="rich")

def key_normalize(key_str) -> int:
    try:
        return int(key_str, 0)
    except ValueError:
        # Try again but this time we prepend a 0x and parse it as a hex
        key_str = "0x" + key_str

    return int(key_str, 16)

@app.command(no_args_is_help=True)
@app.command(no_args_is_help=True)
def extract_usm(
    input: str = typer.Argument(..., help="Path to USM file or path."),
    output: str = typer.Option(
        "./output", "-o", "--output", help="Output path."
    ),
    key: str = typer.Option(
        None,
        "-k",
        "--key",
        help="Decryption key for encrypted USMs.",
        callback=key_normalize,
    ),
    encoding: str = typer.Option(
        "shift-jis", "-e", "--encoding", help="Character encoding used in USM."
    ),
    pages: bool = typer.Option(
        False, "-p", "--pages", help="Toggle to save USM pages when extracting."
    ),
    workers: int = typer.Option(
        4, "-w", "--workers", help="Number of threads to use."
    ),
):
    """Extracts a USM or extracts multiple USMs given a path as input."""

    usmfiles = find_usm(input)

    def process_usm(usmfile):
        try:
            usm = Usm.open(usmfile, encoding=encoding, key=key)
            usm.demux(
                path=output,
                save_video=True,
                save_audio=True,
                save_pages=pages,
                folder_name=usmfile.parent,
            )
        except ValueError:
            print("ERROR")
            print(f"Please run probe on {usmfile}")

    with Progress(
        SpinnerColumn(),
        *Progress.get_default_columns(),
        TimeElapsedColumn(),
    ) as progress:
        task = progress.add_task("Processing...", total=len(usmfiles))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(process_usm, f): f for f in usmfiles}

            for future in as_completed(futures):
                _ = futures[future]  # file reference if needed
                progress.advance(task)
                
                   
@app.command(help="Creates a USM.")
def create_usm(input: str = typer.Argument(..., help="Path to video file."),
               input_audio: str = typer.Option(None, help="Path to audio file."),
               output: str = typer.Option(None, "-o", "--output", help="Output path."),
               ffprobe: str = typer.Option(".", "-f", "--ffprobe", help="Path to ffprobe executable or directory."),
               key: str = typer.Option(None, "-k", "--key", help="Encryption key for encrypted USMs.", callback=key_normalize),
               encoding: str = typer.Option("shift-jis","-e", "--encoding", help="Character encoding used in USM.")
               ):
    app.rich_markup_mode
    ffprobe_path = find_ffprobe(ffprobe)

    # TODO: Add support for more video codecs and audio codecs
    codec = Sofdec2Codec.from_file(input)
    if codec is Sofdec2Codec.VP9:
        video = Vp9(input, ffprobe_path=ffprobe_path)
    elif codec is Sofdec2Codec.H264:
        video = H264(input, ffprobe_path=ffprobe_path)
    else:
        raise NotImplementedError("Non-Vp9/H.264 files are not yet implemented.")

    audios = None
    if input_audio:
        audios = [HCA(input_audio)]

    filename = os.path.splitext(input)[0]

    usm = Usm(videos=[video], audios=audios, key=key)
    with open(filename + ".usm", "wb") as f:
        mode = OpMode.NONE if key is None else OpMode.ENCRYPT

        for packet in usm.stream(mode, encoding=encoding):
            f.write(packet)

    print("Done creating USM file.")

@app.command(help="One of the main functions in the command-line program. Probes a USM or finds multiple USMs and probes them when given a path as input.",no_args_is_help=True)
def probe_usm( input: str = typer.Argument(..., help="Path to video file."),
               output: str = typer.Option(None, "-o", "--output", help="Output path."),
               ffprobe: str = typer.Option(".", "-f", "--ffprobe", help="Path to ffprobe executable or directory."),
               encoding: str = typer.Option("shift-jis","-e", "--encoding", help="Character encoding used in USM.")
               ):

    usmfiles = find_usm(input)

    os.makedirs(output, exist_ok=True)
    temp_dir = tempfile.mkdtemp()
    ffprobe_path = find_ffprobe(ffprobe)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    keys = [
        "levelname",
        "asctime",
        "module",
        "funcName",
        "lineno",
        "message",
    ]
    format_str = " ".join(["%({0:s})s".format(key) for key in keys])
    for i, usmfile in enumerate(usmfiles):
        print(f"Processing {i + 1} of {len(usmfiles)}")

        filename = os.path.basename(usmfile)
        random_str = "".join(random.choices(string.ascii_letters + string.digits, k=3))
        logname = os.path.join(output, f"{filename}_{random_str}.log")

        # Initialize logger
        file_handler = logging.FileHandler(logname, "w", encoding="UTF-8")
        file_handler.setFormatter(jsonlogger.JsonFormatter(format_str))

        [logger.removeHandler(handler) for handler in logger.handlers.copy()]
        logger.addHandler(file_handler)

        # Start logging
        logging.info(
            "Info",
            extra={
                "path": usmfile.replace(input, ""),
                "version": wannacri.__version__,
                "os": f"{platform.system()} {platform.release()}",
                "is_local_ffprobe": ffprobe_path is not None,
            },
        )

        try:
            usm = Usm.open(usmfile, encoding=encoding)
        except ValueError:
            logging.exception("Error occurred in parsing usm file")
            continue

        logging.info("Extracting files")
        try:
            videos, audios = usm.demux(
                path=temp_dir, save_video=True, save_audio=True, save_pages=False
            )
        except ValueError:
            logging.exception("Error occurred in demuxing usm file")
            continue

        logging.info("Probing videos")
        try:
            for video in videos:
                info = ffmpeg.probe(
                    video,
                    show_entries="packet=dts,pts_time,pos,flags",
                    cmd="ffprobe" if ffprobe_path is None else ffprobe_path,
                )
                logging.info(
                    "Video info",
                    extra={
                        "path": video,
                        "format": info.get("format"),
                        "streams": info.get("streams"),
                        "packets": info.get("packets"),
                    },
                )
        except (ValueError, RuntimeError):
            logging.exception("Program error occurred in ffmpeg probe in videos")
            continue
        except ffmpeg.Error as e:
            logging.exception(
                "FFmpeg error occurred in ffmpeg probe in videos.",
                extra={"stderr": e.stderr},
            )
            continue

        logging.info("Probing audios")
        try:
            for audio in audios:
                info = ffmpeg.probe(
                    audio,
                    show_entries="packet=dts,pts_time,pos,flags",
                    cmd="ffprobe" if ffprobe_path is None else ffprobe_path,
                )
                logging.info(
                    "Audio info",
                    extra={
                        "path": audio,
                        "format": info.get("format"),
                        "streams": info.get("streams"),
                        "packets": info.get("packets"),
                    },
                )
        except (ValueError, RuntimeError):
            logging.exception("Program error occurred in ffmpeg probe in audios")
            continue
        except ffmpeg.Error as e:
            logging.exception(
                "FFmpeg error occurred in ffmpeg probe in audios.",
                extra={"stderr": e.stderr},
            )
            continue

        logging.info("Done probing usm file")
        for filename in os.listdir(temp_dir):
            shutil.rmtree(os.path.join(temp_dir, filename))

    shutil.rmtree(temp_dir)
    print(f'Probe complete. All logs are stored in "{output}" folder')

@app.command(help="WannaCRI Encrypt USM/s", no_args_is_help=True)
def encrypt_usm(
    input: str = typer.Argument(..., help="Path to USM file or path."),
    output: str = typer.Option(None, "-o", "--output", help="Output path."),
    key: str = typer.Option(None, "-k", "--key", help="Encryption key", callback=key_normalize),
    encoding: str = typer.Option("shift-jis", "-e", "--encoding", help="Character encoding used in USM."),
    ):
    outdir = dir_or_parent_dir(input) if output is None else pathlib.Path(output)
    usmfiles = find_usm(input)

    for filepath in usmfiles:
        filename = pathlib.PurePath(filepath).name
        usm = Usm.open(filepath)
        usm.video_key, usm.audio_key = generate_keys(key)
        with open(outdir.joinpath(filename), "wb") as out:
            for packet in usm.stream(OpMode.ENCRYPT, encoding=encoding):
                out.write(packet)


def find_usm(directory: str) -> List[Path]:
    """Walks a path to find USMs."""
    if os.path.isfile(directory):
        with open(directory, "rb") as test:
            if not is_usm(test.read(4)):
                raise ValueError("Not a usm file.")

        return [directory]

    print("Finding USM files... ", end="", flush=True)
    usmfiles = []
    files = list(Path(directory).glob('*.usm'))
    for f in files:
        with open(f, "rb") as test:
            if is_usm(test.read(4)):
                usmfiles.append(f)

    print(f"Found {len(usmfiles)}")
    return usmfiles


def find_ffprobe(path: str) -> Optional[str]:
    """Find ffprobe.exe in given path."""
    if os.name != "nt":
        # Assume that ffmpeg is installed in Unix systems
        return

    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        cwdfiles = os.listdir(path)
        for cwdfile in cwdfiles:
            filename = os.path.basename(cwdfile)
            if filename == "ffprobe.exe":
                return os.path.abspath(os.path.join(path, "ffprobe.exe"))





def existing_path(path) -> str:
    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        return path.rstrip("/\\")

    raise FileNotFoundError(path)


def existing_file(path) -> str:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if os.path.isdir(path):
        raise IsADirectoryError(path)

    return path


def dir_path(path) -> str:
    if os.path.isfile(path):
        raise FileExistsError(path)

    return path.rstrip("/\\")

def dir_or_parent_dir(path) -> pathlib.Path:
    path = pathlib.Path(path)
    if path.is_dir():
        return path.parent.resolve()

    return path

def main():
    app()

if __name__ == "__main__":
  app()
