#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import os
import operator

def write_output(output, outf):
    with open(outf, "a+") as f:
        f.write(output)

def report_group(outf, key, lst, group_num):
    output = "Group {0}: {1}\n".format(group_num, key)
    output += (str(len(lst)) + " Members: " + str(lst).strip('[]'))
    write_output(output, outf)

def report_frequency(outf, lst):
    output = "\n Common execution traces in " \
        "slices from the same group by frequency: "
    output += str(lst).strip('[]')
    write_output(output, outf)

# the line before divergence is the first line
# in the input files
def group_by_last_common(in_dir):
    all_files = os.listdir(in_dir)
    res = {}
    for cur in all_files:
        with open(os.path.join(in_dir, cur), "r") as f:
            first_line = f.readline().strip("\n")
        if first_line not in res:
            res[first_line] = []
        res[first_line].append(cur)
    return res
    
def get_frequency(in_dir, lst, num):
    res = {}
    for cur in lst:
        with open(os.path.join(in_dir, cur), "r") as f:
            for line in f:
                if line not in res:
                    res[line] = 0
                res[line] += 1
    sorted_res = sorted(res.items(), key = operator.itemgetter(1), \
                        reverse = True)
    count = min(len(res), num)
    sorted_res = sorted_res[0 : count]
    return sorted_res
    
def cleanup(outf):
    if os.path.exists(outf):
        os.remove(outf)

def analyze(in_dir, outf, num = 20):
    group_dict = group_by_last_common(in_dir)
    group_num = 0
    for key in group_dict:
        report_group(outf, key, group_dict[key], group_num)
        lst = get_frequency(in_dir, group_dict[key], num)
        report_frequency(outf, lst)
        group_num += 1
        write_output("\n\n", outf)

if __name__ == "__main__":
    MAGISK = os.environ["GOPATH"]
    slice_dir = os.path.join(MAGISK, "test_libressl/slices")
    out_dir = os.path.join(MAGISK, "ssl/analysis")
    out_file = os.path.join(out_dir, "group.md")
    cleanup(out_file)
    analyze(slice_dir, out_file)
