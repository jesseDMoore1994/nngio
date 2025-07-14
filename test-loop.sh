#!/usr/bin/env bash
#create LOG_LEVEL variable to control the log level
LOG_LEVEL="ERR"
TESTS_RUN=0
TESTS_PASSED=0

INDENT_2='s/^/  /'
INDENT_4='s/^/    /'
INDENT_8='s/^/        /'

set -o pipefail

inotifywait -m -r -e close_write \
  --include '\.(c|h|cpp|hpp)$' \
  $(pwd) | while read path action file; do

    echo "🚨 Change detected: $file in $path with action $action"

    echo "🔍 Running tests for the mock library" | sed "$INDENT_2"

    echo "🫧 Cleaning previous builds" | sed "$INDENT_4"
    make clean -s | sed "$INDENT_8"

    echo "👷 Building the mock library with log level: $LOG_LEVEL" | sed "$INDENT_4"
    TEST_MOCK=1 make -s -j $(nproc) | sed "$INDENT_8"

    echo "🔍 Running tests for the mock library" | sed "$INDENT_4"
    NNGIO_LOGLEVEL="$LOG_LEVEL" ./build/test_main 2>&1 | sed "$INDENT_8"
    mock_test_result=$?
    if [ $mock_test_result -ne 0 ]; then
      echo "❌ Mock test failed with exit code $mock_test_result" | sed "$INDENT_2"
    else
      echo "✅ Mock tests passed" | sed "$INDENT_2"
      TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    echo ""

    echo "🔍 Running tests for the real library" | sed "$INDENT_2"

    echo "🫧 Cleaning previous builds" | sed "$INDENT_4"
    make clean -s | sed "$INDENT_8"

    echo "👷 Building the real library with log level: $LOG_LEVEL" | sed "$INDENT_4"
    make -s -j $(nproc) | sed "$INDENT_8"

    echo "🔍 Running tests for the real library" | sed "$INDENT_4"
    NNGIO_LOGLEVEL="$LOG_LEVEL" ./build/test_main 2>&1 | sed "$INDENT_8"
    real_test_result=$?
    if [ $real_test_result -ne 0 ]; then
      echo "❌ Real test failed with exit code $real_test_result" | sed "$INDENT_2"
    else
      echo "✅ Real tests passed" | sed "$INDENT_2"
      TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
    echo ""
    TESTS_RUN=$((TESTS_RUN + 1))

    echo "📝 Results summary:"

    if [ $mock_test_result -ne 0 ]; then
      echo "  ❌ Mock test failed with exit code $mock_test_result"
    else
      echo "  ✅ Mock tests passed"
    fi

    if [ $real_test_result -ne 0 ]; then
      echo "  ❌ Real test failed with exit code $real_test_result"
    else
      echo "  ✅ Real tests passed"
    fi

    echo "  Total tests run: $TESTS_RUN"
    echo "  Total tests passed: $TESTS_PASSED"

    if [ $TESTS_RUN -eq $TESTS_PASSED ]; then
      echo "  🎉 All tests passed successfully!"
      if [ "$LOG_LEVEL" = "DBG" ]; then
        echo "    🥾 Bug squashed! Resetting log level to ERR"
        LOG_LEVEL="ERR"
      fi
    else
      echo "  🐞 Some tests failed. Please check the logs above."
      if [ "$LOG_LEVEL" = "ERR" ]; then
        echo "    🔧 Toggling log level to DBG for more information"
        LOG_LEVEL="DBG"
      fi
    fi

done
