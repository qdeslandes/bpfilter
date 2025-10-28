# Bash commands
- Configure CMake: cmake -S $SOURCE_DIR -B $BUILD_DIR -DCMAKE_BUILD_TYPE=$TYPE -DENABLE_COVERAGE=$COVERAGE
    - BUILD_DIR: usually $SOURCE_DIR/build
    - TYPE: `debug` or `release`, use `debug` during development
    - COVERAGE: use 1 for `debug`, and `0` for release
- Build: make -C $BUILD_DIR
- Run tests: make -C build test
    - Run a specific test: `ctest --test-dir $BUILD_DIR --output-on-failure -R "$TEST_NAME"
    - TEST_NAME: path to the test from the `tests` folder: `e2e/matchers/icmp_code.sh` would be `e2e.matchers.icmp_code`, `unit/libbpfilter/list.c` would be `unit.libbpfilter.list.c`.