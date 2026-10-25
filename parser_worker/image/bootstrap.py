"""Fixed image bootstrap. No caller paths, environment dispatch or receiver."""

import sys


def main(arguments: list[str]) -> int:
    if type(arguments) is not list or arguments:
        print("parser_arguments_rejected", file=sys.stderr)
        return 2
    # -I -S excludes working-directory/user site/environment paths. Only these
    # root-owned immutable image directories are added; no .pth file processing.
    sys.path[:0] = ["/opt/sheetsafe/app", "/opt/sheetsafe/vendor"]
    from parser_worker.entrypoint import main as worker_main
    return worker_main([])  # Currently always exits 78: transport unavailable.


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
