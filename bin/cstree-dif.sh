#!/bin/bash

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 out_dir"
	exit 1
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
JQF_DIR=$(dirname $DIR)
BASE_OUT_DIR=$1

OUT_DIR=$BASE_OUT_DIR/cstree-data
mkdir -p $OUT_DIR
mkdir -p $OUT_DIR/random $OUT_DIR/zest

LOG_FILE=$OUT_DIR/experiments.log
touch $LOG_FILE
echo "Start time: $(date)" > $LOG_FILE
echo "Experiment settings: writing to $OUT_DIR, doing 1 repetition" >> $LOG_FILE

BENCHMARKS=(ant maven closure rhino)
TEST_CLASSES=(ant.ProjectBuilderTest maven.ModelReaderTest closure.CompilerTest rhino.CompilerTest)
TEST_METHODS=(testWithGenerator testWithGenerator testWithGenerator testWithGenerator)
CLASSPATH=${JQF_DIR}/scripts/examples_classpath.sh

dir_does_not_exist() {
  if [ -d $1 ]; then
  	echo "$1 already exists, I won't re-run this experiment. Delete the directory and re-run the script if you want me to" >> $LOG_FILE
	return 1
   else
	return 0
   fi
}

for bench_index in {0..3}; do
  BENCHMARK=${BENCHMARKS[$bench_index]}
  TEST_CLASS=${TEST_CLASSES[$bench_index]}
  TEST_METHOD=${TEST_METHODS[$bench_index]}

  echo "======= Starting benchmark: $BENCHMARK =======" >> $LOG_FILE
  for REP_IDX in $(seq 0 4); do
    echo "----- REP: $REP_IDX (started at $(date)) -----" >>$LOG_FILE

    DIRNAME=${OUT_DIR}/zest/$BENCHMARK-$REP_IDX
    if dir_does_not_exist $DIRNAME ; then

      ${JQF_DIR}/bin/jqf-zest -c $($CLASSPATH) edu.berkeley.cs.jqf.examples.$TEST_CLASS $TEST_METHOD ${DIRNAME} &&
      PID=$!
      wait $PID
      echo "[$(date)] Finished zest. No need to replay." >> $LOG_FILE
    fi

    DIRNAME=${OUT_DIR}/random/$BENCHMARK-$REP_IDX
    if dir_does_not_exist $DIRNAME ; then

      ${JQF_DIR}/bin/jqf-zest -b -n -c $($CLASSPATH) edu.berkeley.cs.jqf.examples.$TEST_CLASS $TEST_METHOD ${DIRNAME} &&
      PID=$!
      wait $PID
      echo "[$(date)] Finished random. No need to replay." >> $LOG_FILE
    fi

  done
done

echo "======= End of script reached at $(date) =======" >> $LOG_FILE