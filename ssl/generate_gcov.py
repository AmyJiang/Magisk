#!/usr/bin/python

import argparse
import os
import subprocess
import shutil
from progressbar import ProgressBar, Percentage, Bar, ETA

MAGISK = os.environ["GOPATH"]

def update_output(outf, output):
    with open(outf, 'a') as f:
        f.write(output)

def run_driver(driver, cert):
    try:
        p = subprocess.Popen([driver, cert],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, __ = p.communicate()
        p.wait()
    except Exception:
        raise SystemExit("Running %s failed" % driver)



def generate_gcov(result_dir, out_dir, diffs, driver):
    SUM_F = os.path.join(out_dir, 'gcov.summary')
    print "Generating Line Coverage (total = %d)..."  % len(diffs)
    pbar = ProgressBar(widgets=[Percentage(), ' ', Bar(), ' ',  ETA()],
                       maxval=diffs)

    pargs = [
        "gcovr",
        "--root=/home/amy/repos/cov/libs/libressl/crypto/",
        "-d",
        "-s",
        "-o",
        "/dev/null"
    ]
    for idx in pbar(range(len(diffs))):
        run_driver(driver, os.path.join(result_dir, diffs[idx]))
        p = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = p.communicate()
        p.wait()
        lines = out.splitlines()[0].split("(")[1].split(" ")[0].strip()
        update_output(SUM_F, diffs[idx]+ ":" + lines + "\n")


def analyze(result_dir, out_dir, driver):
    slice_dir = os.path.join(out_dir, "slices")
    diffs = []
    for f in os.listdir(slice_dir):
        if f.endswith(".slice"):
            diffs.append(f.split(".")[0])
    generate_gcov(result_dir, out_dir, diffs, driver)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", default="./final_out",
                        help="directory containing results")
    parser.add_argument("-o", "--out_dir", default="./final_out_analysis",
                        help="directory containing analysis results")
    args = parser.parse_args()

    driver = os.path.join(MAGISK, "ssl/drivers/test_libressl")
    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)

    analyze(args.dir,
            args.out_dir,
            driver)

