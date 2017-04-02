#!/bin/sh

DEST="gen_input"
rm_all() {
    rm -rf mapping.txt;
    rm -rf output.txt;
    rm -rf $DEST;
}

$(rm_all)
TEST_ROOT="../../test_libressl/"
mkdir $DEST 

echo "Copying all necessary inputs to gen_input..."

counter=0
for filename in $TEST_ROOT/diffs/*; do
    mutated=`ls $filename | tr '_' '\n' | tail -1`
    old=`ls $TEST_ROOT/input/* | grep $mutated`
    if [ "$old" != "" ]; then
	echo "Counter $counter: " >> mapping.txt
	echo $(basename $mutated) >> mapping.txt
	echo $(basename $old) >> mapping.txt
	cp $filename $DEST/"$counter"_new
	cp $old $DEST/"$counter"_old
	echo `openssl asn1parse -inform der -in $DEST/"$counter"_new > $DEST/"$counter"_new_readable
	echo `openssl asn1parse -inform der -in $DEST/"$counter"_old > $DEST/"$counter"_old_readable
	counter=$((counter+1))
    fi

done

echo "Generating all traces..."
# cd $TEST_ROOT && make manual_diverg_gen


echo "Extracting addr2line output into output.txt..."
TRACES="gen_traces"
counter=0
max_counter=$((`ls $TRACES | wc -l`/2))
while [ "$counter" -lt "$max_counter" ]; do
    linenum=`diff "$TRACES/$counter"_new.trace "$TRACES/$counter"_old.trace | head -1 | tr 'cd,a' '\n' | head -1`
    echo "Trace number: $counter:\t" >> output.txt
    if [ "$linenum" != "" ]; then
	diffline=$((linenum-1))
	addr=`sed "${diffline}q;d" "$TRACES/$counter"_new.trace | tr ':' '\n' | head -1`
	result=`addr2line -e $TEST_ROOT/test_libressl $addr`
	echo "$result" >> output.txt
    fi
    counter=$((counter+1))
done
