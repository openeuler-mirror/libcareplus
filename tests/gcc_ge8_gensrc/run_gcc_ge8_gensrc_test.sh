#/bin/sh

echo "the following case only for gcc $2 and later:"

CURDIR=$(cd $(dirname $0); pwd)
SOURCE_SET=$(find $CURDIR -name *.orig.s)
TOTAL_CASE=$(find $CURDIR -name sub_desc | wc -l)
KPATCH_GENSRC=$CURDIR/../../src/kpatch_gensrc

OK_CNT=0
FAIL_CNT=0
SKIP_CNT=0

if [ $1 -lt $2 ]; then
    SKIP_CNT=$TOTAL_CASE
    echo "gcc is too old to test, test: gcc $1 < required: gcc $2)"
    echo "OK $OK_CNT FAIL $FAIL_CNT SKIP $SKIP_CNT TOTAL $TOTAL_CASE"
    exit 0
fi

for SOURCE in $SOURCE_SET; do
    FILENAME=${SOURCE##*/}
    CASENAME=${FILENAME%.orig.s}
    if [ $CASENAME == "cold_func_suffix" ]; then
        KEY_WORD="\.cold."
    else
        KEY_WORD=$CASENAME
    fi

    KEY_WORD_LINE=$(grep -c $KEY_WORD $SOURCE)
    if [ $KEY_WORD_LINE -lt "2" ]; then
        echo "SKIP: $CASENAME, $KEY_WORD not found"
        SKIP_CNT=$(($SKIP_CNT+1))
        continue
    fi

    $KPATCH_GENSRC --os=rhel6 -i $SOURCE -i $SOURCE -o ${SOURCE/.orig/.o}
    sed -i '/^#/d' ${SOURCE/.orig/.o}

    DIFF_LINE=$(diff $SOURCE ${SOURCE/.orig/.o} | grep -c $KEY_WORD)
    if [ $DIFF_LINE -gt "0" ]; then
        echo "TEST $CASENAME IS FAIL"
        FAIL_CNT=$(($FAIL_CNT+1))
    else
        echo "TEST $CASENAME IS OK"
        OK_CNT=$(($OK_CNT+1))
    fi
done

echo "OK $OK_CNT FAIL $FAIL_CNT SKIP $SKIP_CNT TOTAL $TOTAL_CASE"
exit 0