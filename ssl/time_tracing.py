#!/usr/bin/python

import argparse
import os
import subprocess
import time
from progressbar import ProgressBar, Percentage, Bar, ETA

MAGISK = os.environ["GOPATH"]

def update_output(outf, output):
    with open(outf, 'a') as f:
        f.write(output)

def time_tracing(result_dir, out_dir, diffs, driver):
    SUM_F = os.path.join(out_dir, 'time.summary')
    print "Time tracing (total = %d)..."  % len(diffs)
    pbar = ProgressBar(widgets=[Percentage(), ' ', Bar(), ' ',  ETA()],
                       maxval=diffs)

    pargs = [
        "/home/amy/repos/pin-3.2-81205-gcc-linux/pin",
        "-t",
        "/home/amy/repos/magisk/src/ExecTrace/obj-intel64/exectrace.so",
        "-magisk",
        "0",
        "-mem", "1",
        "-o",
        "test.trace",
        "--",
        "/home/amy/repos/magisk/ssl/drivers/test_libressl",
        "INPUT"
    ]
    FNULL = open(os.devnull, 'w')
    for idx in pbar(range(len(diffs))):
        cert = os.path.join(result_dir, diffs[idx])
        try:
            pargs[-1] = cert
            start = time.time()
            ret = subprocess.call(pargs, stdout=FNULL, stderr=FNULL)
            end = time.time()
        except Exception as e:
            raise SystemExit("Running %s failed" % " ".join(pargs))
        update_output(SUM_F, diffs[idx]+ ":" + str(end - start) + "\n")


def analyze(result_dir, out_dir, driver):
    diffs = []
    for f in os.listdir(result_dir):
        if 'BeforeMutation' not in f and "slow-unit" not in f:
            diffs.append(f)

    time_tracing(result_dir, out_dir, diffs, driver)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True,
                        help="directory containing results")
    parser.add_argument("-o", "--out_dir", default="./analysis",
                        help="directory containing analysis results")
    args = parser.parse_args()

    driver = os.path.join(MAGISK, "ssl/drivers/test_libressl")
    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)

    analyze(args.dir,
            args.out_dir,
            driver)

