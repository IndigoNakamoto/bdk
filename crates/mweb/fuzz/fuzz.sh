#!/usr/bin/env bash
# Briefly fuzz every bdk_mweb target, as CI does.
# Usage: ./fuzz.sh [target-name]
set -euox pipefail

REPO_DIR=$(git rev-parse --show-toplevel)

# shellcheck source=./fuzz-util.sh
source "$REPO_DIR/crates/mweb/fuzz/fuzz-util.sh"

cd "$FUZZ_DIR"

checkWindowsFiles

if [ "${1:-}" == "" ]; then
  targetFiles="$(listTargetFiles)"
else
  targetFiles=fuzz_targets/"$1".rs
fi

cargo --version
rustc --version

cargo install --force honggfuzz --no-default-features

for targetFile in $targetFiles; do
  targetName=$(targetFileToName "$targetFile")
  echo "Fuzzing target $targetName ($targetFile)"
  if [ -d "hfuzz_input/$targetName" ]; then
    HFUZZ_INPUT_ARGS="-f hfuzz_input/$targetName/input\""
  else
    HFUZZ_INPUT_ARGS=""
  fi
  HFUZZ_RUN_ARGS="--run_time ${RUN_TIME:-60} --exit_upon_crash -v $HFUZZ_INPUT_ARGS" cargo hfuzz run "$targetName"

  checkReport "$targetName"
done
