#!/usr/bin/python
# Required: export PYTHONPATH=/home/amy/repos/magisk/src/slicer:$PYTHONPATH

import argparse
import os
import subprocess
from threading import Timer
from progressbar import ProgressBar, Percentage, Bar, ETA

MAGISK = os.environ["GOPATH"]
TIMEOUT = 60.0

def update_output(outf, output):
    with open(outf, 'a') as f:
        f.write(output)


def generate_slice(result_dir, driver, start_bbls):
    trace_dir = os.path.join(result_dir, "traces")
    slice_dir = os.path.join(result_dir, "slices")
    LOG_F = os.path.join(slice_dir, "slice.log")

    if not os.path.exists(slice_dir):
        os.makedirs(slice_dir)

    print "Generating Slice..."
    pbar = ProgressBar(widgets=[Percentage(), ' ', Bar(), ' ', ETA()],
                       maxval=start_bbls)

    kill = lambda process: process.kill()

    for trace, num_bbl in pbar(start_bbls):
        pargs = [
            os.path.join(MAGISK, "src/slicer/slicer.py"),
            os.path.abspath(driver), #bin
            os.path.abspath(os.path.join(trace_dir, trace.strip()+".trace")), #trace
            num_bbl,
            os.path.abspath(os.path.join(slice_dir, trace.strip()+".slice")), #trace
        ]
        p = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timer = Timer(TIMEOUT, kill, [p])
        try:
            timer.start()
            _, err = p.communicate()
        finally:
            timer.cancel()
            update_output(LOG_F, err)

def parse_summary(sum_f):
    # parse the summary file, each line of the file is in the format:
    # input_name:[true|false]:num_of_bbl(to start slicing)
    start_bbls = []
    with open(sum_f, 'r') as inf:
        for line in inf.readlines():
            fields = line.strip().split(":")
            if len(fields) < 3 or fields[1] != 'false':
                continue
            start_bbls.append((fields[0], fields[2]))
    print 'Parsed summary: %d trace' % len(start_bbls)
    return start_bbls

def analyze(result_dir, driver):
    SUM_F = os.path.join(result_dir, "trace.summary")
    start_bbls = parse_summary(SUM_F)
    generate_slice(result_dir, driver, start_bbls)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True,
                        help="directory containing traces (and summary)")
    args = parser.parse_args()

    analyze(args.dir, os.path.join(MAGISK, "ssl/drivers/test_libressl"))
