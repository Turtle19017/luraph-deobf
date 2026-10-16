#!/usr/bin/env python3
"""
run_luau_capture.py - run a Luau file and ALWAYS keep whatever it printed,
even if it times out or is killed.

The protected target can legitimately run for a very long time once it gets
past its environment probes, so a hard timeout must not discard the trace.
"""
import argparse, io, os, signal, subprocess, sys, threading, time


def main():
    # Windows consoles may default to cp1252. Captured Luau output is decoded
    # as UTF-8 with replacement, so make our own diagnostic printing equally
    # robust instead of crashing on U+FFFD or other non-CP1252 characters.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser()
    ap.add_argument("luau")
    ap.add_argument("target")
    ap.add_argument("-o", "--out", default="capture.txt")
    ap.add_argument("--timeout", type=float, default=300.0)
    args = ap.parse_args()

    fh = io.open(args.out, "w", encoding="utf-8", errors="replace", newline="\n")
    proc = subprocess.Popen(
        [args.luau, args.target],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )

    n = [0]
    t0 = time.time()

    def reader():
        for line in proc.stdout:
            fh.write(line)
            n[0] += 1
            if n[0] % 2000 == 0:
                fh.flush()

    th = threading.Thread(target=reader, daemon=True)
    th.start()

    status = "completed"
    try:
        proc.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        status = "timeout"
        # NOTE: do NOT use CTRL_BREAK_EVENT -- luau.exe drops into its interactive
        # debug REPL and stops consuming the pipe.
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    fh.flush()
    th.join(timeout=3)
    fh.close()

    txt = io.open(args.out, encoding="utf-8", errors="replace").read()
    lines = txt.split("\n")
    print(f"[run] {status} after {time.time()-t0:.1f}s, exit={proc.returncode}, "
          f"{n[0]:,} lines, {len(txt):,} chars -> {args.out}")

    print("\n=== markers ===")
    for pat in ("[A99]", "[A321]", "[A438]", "[A365]", "[AFINALMETA]", "[AFINALLEN]", "[AFINALENTRY]", "[AFINAL11]", "[L3CHUNK]", "[L3VP8]", "[L3TAIL]", "[L3TERM]", "[runner]"):
        hits = [l for l in lines if l.startswith(pat)]
        if hits:
            for h in hits[:4]:
                print("  " + h)
            if len(hits) > 4:
                print(f"  ... {len(hits)} total")
        else:
            print(f"  {pat:<7} (never reached)")

    a228 = [l for l in lines if l.startswith("[A228]")]
    print(f"\n[A228] count = {len(a228):,}")
    if a228:
        print("  first:", a228[0])
        print("  last :", a228[-1])

    at = [l for l in lines if l.startswith("[A]")]
    if at:
        print(f"\n=== [A] interpreter opcode stream: {len(at):,} lines ===")
        print("  " + "  ".join(l.split("\t")[1] if "\t" in l else l for l in at[:120]))
        print("  ...")
        print("  " + "  ".join(l.split("\t")[1] if "\t" in l else l for l in at[-20:]))

    print("\n=== last 15 lines ===")
    for l in lines[-15:]:
        if l.strip():
            print("  " + l)


if __name__ == "__main__":
    main()