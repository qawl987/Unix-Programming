#!/bin/bash

# Script to run a single test case for sdb
# It expects two arguments:
# $1: TEST_NAME (e.g., "ex1-1", used for finding .txt files)
# $2: TEST_PROGRAM (e.g., "hello", the program to be debugged by sdb)

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <TEST_NAME> <TEST_PROGRAM>"
    echo "Example: $0 ex1-1 hello"
    exit 1
fi

TEST_NAME="$1"
TEST_PROGRAM_NAME="$2" # The name of the program to test, e.g., hello, hola

SDB_EXECUTABLE="./sdb" # Assumes sdb is in the current directory
COMMANDS_FILE="./test_case/${TEST_NAME}.txt"
EXPECTED_OUTPUT_FILE="./ans/${TEST_NAME}.txt"
ACTUAL_OUTPUT_DIR="./output"
ACTUAL_OUTPUT_FILE="${ACTUAL_OUTPUT_DIR}/${TEST_NAME}.txt"

# --- Sanity Checks ---
# Ensure sdb executable exists
if [ ! -f "$SDB_EXECUTABLE" ]; then
    echo "Error: sdb executable '$SDB_EXECUTABLE' not found. Please build it first (e.g., using 'make all')."
    exit 1
fi

# Determine the path to the test program (e.g., hello, hola)
# Check current directory first, then a common 'test_programs' subdirectory
TEST_PROGRAM_PATH="./${TEST_PROGRAM_NAME}"
if [ ! -x "$TEST_PROGRAM_PATH" ]; then # Check if it's executable
    ALT_TEST_PROGRAM_PATH="./test_programs/${TEST_PROGRAM_NAME}"
    if [ ! -x "$ALT_TEST_PROGRAM_PATH" ]; then
        echo "Error: Test program '$TEST_PROGRAM_NAME' not found or not executable at '$TEST_PROGRAM_PATH' or '$ALT_TEST_PROGRAM_PATH'."
        echo "Please ensure it is built and placed in one of these locations."
        exit 1
    fi
    TEST_PROGRAM_PATH="$ALT_TEST_PROGRAM_PATH"
fi


# Ensure commands file exists
if [ ! -f "$COMMANDS_FILE" ]; then
    echo "Error: Commands file '$COMMANDS_FILE' for test '$TEST_NAME' not found."
    exit 1
fi

# Ensure expected output file exists
if [ ! -f "$EXPECTED_OUTPUT_FILE" ]; then
    echo "Error: Expected output file '$EXPECTED_OUTPUT_FILE' for test '$TEST_NAME' not found."
    exit 1
fi

# --- Running the Test ---
echo "Running sdb for test '$TEST_NAME' on program '$TEST_PROGRAM_PATH'..."
echo "Commands from: $COMMANDS_FILE"
echo "sdb executable: $SDB_EXECUTABLE"

# Run sdb with the test program as an argument and redirect input/output
# This assumes your sdb takes the program to debug as a command-line argument.
# If sdb loads the program via an internal command (e.g., 'load <program>' from COMMANDS_FILE),
# you might not need to pass $TEST_PROGRAM_PATH to sdb here.
"$SDB_EXECUTABLE" < "$COMMANDS_FILE" > "$ACTUAL_OUTPUT_FILE"
SDB_EXIT_CODE=$?

if [ $SDB_EXIT_CODE -ne 0 ]; then
    echo "Warning: sdb exited with code $SDB_EXIT_CODE for test '$TEST_NAME'."
    # Depending on your sdb's behavior, this might or might not indicate a test failure.
    # The diff below is the primary check.
fi

# --- Comparing Output ---
echo "Comparing actual output ('$ACTUAL_OUTPUT_FILE') with expected output ('$EXPECTED_OUTPUT_FILE')..."

if diff -u "$EXPECTED_OUTPUT_FILE" "$ACTUAL_OUTPUT_FILE"; then
    echo ""
    echo "----------------------------------------"
    echo "✅ TEST '$TEST_NAME' PASSED: Output matches expected."
    echo "----------------------------------------"
    # You might want to remove the actual output file on success:
    # rm "$ACTUAL_OUTPUT_FILE"
    exit 0
else
    echo ""
    echo "--------------------------------------------------------------------"
    echo "❌ TEST '$TEST_NAME' FAILED: Output does NOT match expected. See diff above."
    echo "Expected output is in: $EXPECTED_OUTPUT_FILE"
    echo "Actual output is in  : $ACTUAL_OUTPUT_FILE"
    echo "--------------------------------------------------------------------"
    exit 1
fi
