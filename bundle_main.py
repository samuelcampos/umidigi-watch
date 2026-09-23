"""Runs inside Uwatch.app under LaunchServices.

macOS refuses Bluetooth to a process whose *responsible* process has no
Bluetooth usage description, which rules out running straight from a shell.
Launching the bundle with `open` makes it responsible for itself, but then it
has no terminal - so mirror stdout/stderr into a file the launcher tails.
"""
import os
import sys
from pathlib import Path

MARKER = "__UWATCH_EXIT__"


def main() -> None:
    out_path = Path(sys.argv[1])
    args = sys.argv[2:]
    sys.path.insert(0, str(Path(__file__).resolve().parent))

    with out_path.open("w", buffering=1, encoding="utf-8", errors="replace") as out:
        os.dup2(out.fileno(), 1)
        os.dup2(out.fileno(), 2)
        sys.stdout = sys.stderr = out
        code = 1
        try:
            from uwatch.cli import main as cli_main
            code = cli_main(args)
        except SystemExit as exc:
            if isinstance(exc.code, int) or exc.code is None:
                code = exc.code or 0
            else:
                print(exc.code, file=out)
                code = 1
        except BaseException:
            import traceback
            traceback.print_exc()
        finally:
            out.write(f"\n{MARKER}{code}\n")
            out.flush()
            os.fsync(out.fileno())


if __name__ == "__main__":
    main()
