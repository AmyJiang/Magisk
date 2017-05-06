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

def generate_trace(result_dir, out_dir, diffs, driver, batch=40):
    LOG_F = os.path.join(out_dir, 'trace.log')
    SUM_F = os.path.join(out_dir, 'trace.summary')

    input_d = os.path.join(out_dir, "input")
    query_d = os.path.join(out_dir, "query")
    shutil.rmtree(query_d, ignore_errors=True)
    shutil.rmtree(input_d, ignore_errors=True)


    print "Write log to file %s" % LOG_F
    print "Write summary to file %s" % SUM_F

    print "Generating Trace (total = %d)..."  % len(diffs)
    pbar = ProgressBar(widgets=[Percentage(), ' ', Bar(), ' ',  ETA()],
                       maxval=diffs)


    pargs = [
        os.path.join(MAGISK, "bin/debugger"),
        "-bin", os.path.abspath(driver),
        "-pin", os.path.abspath(os.path.join(os.environ["PIN_ROOT"], "pin")),
        "-dir", os.path.abspath(out_dir),
        "-procs", "4",
    ]
    print " ".join(pargs)

    for idx in pbar(range(0, len(diffs), batch)):
        os.mkdir(input_d)
        os.mkdir(query_d)
        for q, i in diffs[idx:idx+batch]:
            shutil.copy2(os.path.join(result_dir, i), input_d)
            shutil.copy2(os.path.join(result_dir, q), query_d)

        p = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        update_output(SUM_F, out)
        update_output(LOG_F, err)

        shutil.rmtree(query_d, ignore_errors=True)
        shutil.rmtree(input_d, ignore_errors=True)


def pair_up_diffs(result_dir):
    originals = dict()
    diffs = []
    for f in os.listdir(result_dir):
        if "BeforeMutation" in f:
            h = f.strip().split("_")[0]
            originals[h] = f

    for f in os.listdir(result_dir):
        if "BeforeMutation" not in f:
            h = f.strip().split("_")[-1]
            if h in originals:
                diffs.append((f, originals[h]))
    return diffs


def analyze(result_dir, llist, out_dir):
    diffs = pair_up_diffs(result_dir)
    generate_trace(result_dir, out_dir, diffs, llist[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True,
                        help="directory containing results")
    parser.add_argument("-o", "--out_dir", default="./analysis/",
                        help="output directory")
    args = parser.parse_args()

    lib_list = [
        os.path.join(MAGISK, "test_libressl/test_libressl"),
        os.path.join(MAGISK, "ssl/drivers/test_openssl"),
    ]

    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)

    analyze(args.dir,
            lib_list,
            args.out_dir)

