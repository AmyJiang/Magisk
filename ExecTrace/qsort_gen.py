import os
import subprocess

DIR = "qsort_gen"

if __name__ == "__main__":
    test_seq = 0
    with open("qsort_input.txt") as in_file:
        inputs = in_file.readlines()
    if not os.path.exists(DIR):
        os.makedirs(DIR)
    
    for i in range(len(inputs)):
        with open("qsort_test.txt", 'w') as test_file:
            test_file.write(inputs[i])

        subprocess.check_call(["/usr/bin/make", "qsort"])
        os.rename("exectrace.out", os.path.join(DIR, str(test_seq) + "_exectrace.out"))
        test_seq += 1
        



