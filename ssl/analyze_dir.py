#!/usr/bin/python

import argparse
import difflib
import hashlib
import os
import shutil
import subprocess
import sys
import traceback

from progressbar import ProgressBar, Percentage, Bar, ETA

def cert_chain_asn1info(cert, sslbin):
    if not os.path.isfile(cert):
        return ""

    pargs = [
        sslbin,
        "asn1parse",
        "-dump",
        "-inform",
        "DER",
        "-in",
        cert
    ]
    p = subprocess.Popen(pargs,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)

    out, _ = p.communicate()
    return out

def diff_asn1parse(after, before, sslbin):
    output = ""
    output += "\n\n####asn1parse output diff\n"
    output += "\n```\n"
    diff = difflib.Differ().compare(cert_chain_asn1info(after, sslbin).splitlines(),
                                    cert_chain_asn1info(before, sslbin).splitlines())
    output += ''.join([line for line in diff if not line.startswith(' ')])
    output += "\n```\n"
    return output

def reproduce_diff(cert, driver):
    output = ""
    try:
        p = subprocess.Popen([driver, cert],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        output, _ = p.communicate()
    except Exception:
        traceback.print_exc(file=sys.stdout)
        raise SystemExit("Running %s failed" % driver)
    return output


def diff_driver_output(after, before, llist):
    output = ""
    output += "\n\n####Driver output\n"

    for lib in llist:
        output += "\n\n#####Driver: " + lib + "\n"
        output += "\n```\n"
        output += reproduce_diff(after, lib)
        output += "\n```\n"
    return output


def analyze(result_dir, ca, llist, blist, outdir):
    before_mutations = dict()
    diffs = []

    if not os.path.exists(outdir) or not os.path.isdir(outdir):
        os.makedirs(outdir)

    for f in os.listdir(result_dir):
        if "BeforeMutation" in f:
            h = f.strip().split("_")[0]
            before_mutations[h] = f

    for f in os.listdir(result_dir):
        if "BeforeMutation" not in f:
            h = f.strip().split("_")[-1]
            if h in before_mutations:
                diffs.append((f, before_mutations[h]))

    print "Analyzing results"
    pbar = ProgressBar(widgets=[Percentage(), ' ', Bar(), ' ',  ETA()],
                       maxval=diffs)

    for after, before in pbar(diffs):
        after_f = os.path.join(result_dir, after)
        before_f = os.path.join(result_dir, before)
        output = ""
        output += "###File: " + after_f + "\n\n"
        output += "Before Mutation: " + before_f + "\n\n"
        output += diff_driver_output(after_f, before_f, llist)
        output += diff_asn1parse(after_f, before_f, blist[0])

        write_output(output, outdir, after)


def write_output(output, outdir, cert):
    outf = os.path.join(outdir, cert) + ".md"
    with open(outf, "w") as f:
        f.write("Analysis\n======================\n\n")
        f.write(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", required=True,
                        help="directory containing results")
    parser.add_argument("-c", "--ca", default="",
                        help="root ca")
    parser.add_argument("-o", "--out_dir", default="./analysis/",
                        help="output directory")
    args = parser.parse_args()

    MAGISK = os.environ["GOPATH"]

    lib_list = [
    #    os.path.join(MAGISK, "ssl/drivers/test_openssl"),
        os.path.join(MAGISK, "ssl/drivers/test_libressl"),
    ]

    bin_list = [
    #    os.path.join(MAGISK, "builds/openssl/bin/openssl"),
        os.path.join(MAGISK, "builds/libressl/bin/openssl"),
    ]

    analyze(args.dir,
            args.ca,
            lib_list,
            bin_list,
            args.out_dir)
