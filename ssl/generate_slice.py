#!/usr/bin/python

import argparse
import os
import subprocess
import sys
import traceback
import logging
import shutil


MAGISK = os.environ["GOPATH"]

def rmdir(d):
    if os.path.exists(d):
        shutil.rmtree(d)


def generate_slice(result_dir, out_dir, diffs, driver, batch=10):
    global MAGISK

    input_d = out_dir + "/input"
    query_d = out_dir + "/query"
    output = ""

    print "Generating Slice"
    for idx in range(0, len(diffs), batch):
        rmdir(input_d)
        rmdir(query_d)
        os.mkdir(input_d)
        os.mkdir(query_d)

        for q, i in diffs[idx:idx+batch]:
            shutil.copy2(result_dir + "/" + i, input_d)
            shutil.copy2(result_dir + "/" + q, query_d)

        pargs = [
            os.path.join(MAGISK, "bin/debugger"),
            "-bin", driver,
            "-pin", os.path.join(os.environ["PIN_ROOT"], "pin"),
            "-dir", out_dir,
            "-procs", "2",
            "-slice"
        ]
        print "\tRunning #%d-#%d" % (idx, idx+batch if idx+batch < len(diffs) else len(diffs)-1)
        print "\t", " ".join(pargs)
        p = subprocess.Popen(pargs)
        out, _ = p.communicate()
        if out:
            output += out

    rmdir(input_d)
    rmdir(query_d)
    return output


def analyze(result_dir, llist, out_dir):
    before_mutations = dict()
    diffs = []
    if not os.path.exists(out_dir) or not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    for f in os.listdir(result_dir):
        if "BeforeMutation" in f:
            h = f.strip().split("_")[0]
            before_mutations[h] = f

    for f in os.listdir(result_dir):
        if "BeforeMutation" not in f:
            h = f.strip().split("_")[-1]
            if h in before_mutations:
                diffs.append((f, before_mutations[h]))

    generate_slice(result_dir, out_dir, diffs, llist[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True,
                        help="directory containing results")
    parser.add_argument("-o", "--out_dir", default="analysis/",
                        help="output directory")
    args = parser.parse_args()

    lib_list = [
        os.path.join(MAGISK, "ssl/drivers/test_libressl"),
        os.path.join(MAGISK, "ssl/drivers/test_openssl"),
    ]

    analyze(args.dir,
            lib_list,
            args.out_dir)


