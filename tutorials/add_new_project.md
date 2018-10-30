# Steps to add new project

## 0. Requirements

1. GSL https://github.com/imatix/gsl

## 1. Create project file

Add file `project_<name>.xml` to the `codegen/project`.

Specify required modules, classes, interfaces.

Add correspond entity `project` to file `codegen/main.xml`

Run code generation script `codegen.sh`.

## 2. Add CMake files

Add project `CMakeLisst.txt` file

Add `Config.cmake.in` file

