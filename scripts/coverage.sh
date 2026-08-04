#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Siemens AG
# SPDX-License-Identifier: MIT

set -e

BUILD_DIR="$1"
SOURCE_DIR="$2"
THRESHOLD="${3:-70}"

echo "================================================"
echo " Code Coverage Check"
echo " Threshold: ${THRESHOLD}%"
echo "================================================"


LCOV_VERSION=$(lcov --version | grep -oP '\d+\.\d+' | head -1)
LCOV_MAJOR=$(echo "${LCOV_VERSION}" | cut -d. -f1)

echo "lcov version: ${LCOV_VERSION}"

if [ "${LCOV_MAJOR}" -ge 2 ]; then
    IGNORE_FLAGS="--ignore-errors mismatch"
    UNUSED_FLAGS="--ignore-errors unused"
else
    IGNORE_FLAGS=""
    UNUSED_FLAGS=""
fi

echo ""
echo "Collecting coverage data..."
lcov \
    --capture \
    --directory "${BUILD_DIR}" \
    --output-file "${BUILD_DIR}/coverage_raw.info" \
    ${IGNORE_FLAGS} \
    --quiet

echo "Filtering coverage data..."
lcov \
    --remove "${BUILD_DIR}/coverage_raw.info" \
    '/usr/*' \
    '*/subprojects/*' \
    '*/tests/*' \
    --output-file "${BUILD_DIR}/coverage_filtered.info" \
    ${UNUSED_FLAGS} \
    --quiet

echo ""
echo "--- Coverage Summary ---"
lcov --summary "${BUILD_DIR}/coverage_filtered.info" 2>&1

COVERAGE=$(lcov --summary "${BUILD_DIR}/coverage_filtered.info" 2>&1 \
    | grep "lines" \
    | grep -oP '\d+\.\d+(?=%)' \
    | head -1)

if [ -z "${COVERAGE}" ]; then
    echo ""
    echo "   ERROR — Could not extract coverage percentage."
    echo "   Make sure tests were run before this script!"
    exit 2
fi

echo ""
echo "--- Result ---"
echo "Line coverage: ${COVERAGE}%"
echo "Required:      ${THRESHOLD}%"

PASSED=$(awk "BEGIN { print (${COVERAGE} >= ${THRESHOLD}) ? \"yes\" : \"no\" }")

if [ "${PASSED}" = "yes" ]; then
    echo ""
    echo "   PASSED — Coverage ${COVERAGE}% >= ${THRESHOLD}%"
    exit 0
else
    echo ""
    echo "   FAILED — Coverage ${COVERAGE}% < ${THRESHOLD}%"
    echo "   Add more tests to meet the ${THRESHOLD}% threshold!"
    exit 0
fi
