#!groovy


// --------------------------------------------------------------------------
//  Configuration properties.
// --------------------------------------------------------------------------
properties([
    parameters([
        booleanParam(name: 'RUN_ANDROID_TESTS', defaultValue: true,
            description: 'Run Android instrumental tests.'),

        booleanParam(name: 'DISABLE_PHP_BUILDS', defaultValue: false,
            description: 'Disable build of PHP artifacts'),

        booleanParam(name: 'DISABLE_JAVA_BUILDS', defaultValue: false,
            description: 'Disable build of Java artifacts'),

        booleanParam(name: 'DISABLE_PYTHON_BUILDS', defaultValue: false,
            description: 'Disable build of Python artifacts'),

        booleanParam(name: 'DEPLOY_JAVA_ARTIFACTS', defaultValue: false,
            description: 'If build succeeded then Java artifacts will be deployed to the Maven repository.'),

        booleanParam(name: 'DEPLOY_ANDROID_ARTIFACTS', defaultValue: false,
            description: 'If build succeeded then Java Android artifacts will be deployed to the Maven repository.'),

        booleanParam(name: 'DEPLOY_PYTHON_ARTIFACTS', defaultValue: false,
            description: 'If build succeeded then Python artifacts will be deployed to the Pip repository.'),

        string(name: 'gpg_keyname', defaultValue: 'B2007BBB'),
    ])
])


// --------------------------------------------------------------------------
//  Grab SCM
// --------------------------------------------------------------------------

node('master') {
    stage('Grab SCM') {
        env
        echo "RUN_ANDROID_TESTS = ${params.RUN_ANDROID_TESTS}"
        echo "DEPLOY_JAVA_ARTIFACTS = ${params.DEPLOY_JAVA_ARTIFACTS}"
        echo "DEPLOY_ANDROID_ARTIFACTS = ${params.DEPLOY_ANDROID_ARTIFACTS}"
        echo "DEPLOY_PYTHON_ARTIFACTS = ${params.DEPLOY_PYTHON_ARTIFACTS}"
        clearContentUnix()
        checkout scm
        stash includes: '**', name: 'src'
        archiveArtifacts('VERSION')
    }
}


// --------------------------------------------------------------------------
//  Build
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
//  Create parallel build for all nodes
// --------------------------------------------------------------------------
def nodes = [:]

//
//  Language: C
//
nodes['lang-c-platform-linux'] = build_LangC_Unix('build-centos7', 'x86_64')
nodes['lang-c-platform-macos-x86_64'] = build_LangC_Unix('build-os-x', 'x86_64')
nodes['lang-c-platform-macos-arm64'] = build_LangC_Unix('build-os-x', 'arm64')
nodes['lang-c-platform-windows'] = build_LangC_Windows('build-win10')

//
//  Language: PHP
//
if (!params.DISABLE_PHP_BUILDS) {
    nodes['lang-php-platform-linux'] = build_LangPHP_Linux('build-centos7')
    nodes['lang-php-platform-macos-x86_64'] = build_LangPHP_MacOS('build-os-x', 'x86_64')
    nodes['lang-php-platform-macos-arm64'] = build_LangPHP_MacOS('build-os-x', 'arm64')
    nodes['lang-php-platform-windows'] = build_LangPHP_Windows('build-win10')
}


//
//  Language: Java
//
if (!params.DISABLE_JAVA_BUILDS) {
    nodes['lang-java-platform-linux'] = build_LangJava_Linux('build-centos7')
    nodes['lang-java-platform-macos-x86_64'] = build_LangJava_MacOS('build-os-x', 'x86_64')
    nodes['lang-java-platform-macos-arm64'] = build_LangJava_MacOS('build-os-x', 'arm64')
    nodes['lang-java-platform-windows'] = build_LangJava_Windows('build-win10')
    nodes['lang-java-platform-android-x86'] = build_LangJava_Android_x86('build-os-x')
    nodes['lang-java-platform-android-x86_64'] = build_LangJava_Android_x86_64('build-os-x')
    nodes['lang-java-platform-android-armeabi-v7a'] = build_LangJava_Android_armeabi_v7a('build-os-x')
    nodes['lang-java-platform-android-arm64-v8a'] = build_LangJava_Android_arm64_v8a('build-os-x')
}


//
// Language: Python
//
if (!params.DISABLE_PYTHON_BUILDS) {
    nodes['lang-python-platform-linux'] = build_LangPython_Linux('build-centos7')
    nodes['lang-python-platform-macos-x86_64'] = build_LangPython_MacOS('build-os-x', 'x86_64')
    nodes['lang-python-platform-macos-arm64'] = build_LangPython_MacOS('build-os-x', 'arm64')
    nodes['lang-python-platform-windows-x86'] = build_LangPython_Windows('build-win10', 'x86')
    nodes['lang-python-platform-windows-x86_64'] = build_LangPython_Windows('build-win10', 'x86_64')
}

stage('Build') {
    parallel(nodes)
}


// --------------------------------------------------------------------------
//  Helper functions
// --------------------------------------------------------------------------
def clearContentUnix() {
    sh 'rm -fr -- *'
}

def clearContentWindows() {
    bat "(for /F \"delims=\" %%i in ('dir /b') do (rmdir \"%%i\" /s/q >nul 2>&1 || del \"%%i\" /s/q >nul 2>&1 )) || rem"
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}

def pathFromJobName(jobName) {
    return jobName.replace('/','-').replace('%2f', '-').replace('%2F', '-')
}

def cleanPythonBuildDirectoriesLinux(){
    sh "find virgil_crypto_lib/ -name '*.pyc' -delete"
    sh "rm -rf build/"
    sh "rm -rf *.egg-info"
}

// --------------------------------------------------------------------------
//  Build nodes for language: C
// --------------------------------------------------------------------------
def build_LangC_Unix(slave, arch) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            def optimisationOptions = ""
            def canRunTest = false
            if (arch == "x86_64") {
                optimisationOptions = "-DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF"
                canRunTest = true
            }

            clearContentUnix()
            unstash 'src'
            sh """
                cmake -DCMAKE_BUILD_TYPE=Release ${optimisationOptions} \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=${arch} \
                      -DCMAKE_OSX_ARCHITECTURES=${arch} \
                      -DCPACK_OUTPUT_FILE_PREFIX=c \
                      -DENABLE_CLANGFORMAT=OFF \
                      -DVIRGIL_C_MT_TESTING=ON \
                      -Bbuild -H.
                cmake --build build -- -j10
            """
            dir('build') {
                if (canRunTest) {
                    sh "ctest --verbose"
                }
                sh "cpack"
                archiveArtifacts('c/**')
            }
        }
    }}
}

def build_LangC_Windows(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace\\${jobPath}") {
            clearContentWindows()
            unstash 'src'
            bat '''
                set PATH=%PATH:"=%
                call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
                cmake -G"NMake Makefiles" ^
                      -DCMAKE_BUILD_TYPE=Release ^
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=x86_64 ^
                      -DVIRGIL_LIB_PYTHIA=OFF ^
                      -DCPACK_OUTPUT_FILE_PREFIX=c ^
                      -DENABLE_CLANGFORMAT=OFF ^
                      -DVIRGIL_C_MT_TESTING=ON ^
                      -Bbuild -H.
                cmake --build build
                cd build
                ctest --verbose
                cpack
            '''
            dir('build') {
                archiveArtifacts('c/**')
            }
        }
    }}
}

// --------------------------------------------------------------------------
//  Build nodes for language: PHP
// --------------------------------------------------------------------------
def build_LangPHP_Linux(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            sh '''
                source /opt/remi/php73/enable
                cmake -Cconfigs/php-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=$(uname -m) \
                      -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.3 \
                      -DCPACK_OUTPUT_FILE_PREFIX=php \
                      -DENABLE_CLANGFORMAT=OFF \
                      -DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF \
                      -Bbuild -H.
                cmake --build build -- -j10
                cd build
                ctest --verbose
                cpack
            '''
            dir('build') {
                archiveArtifacts('php/**')
            }

            clearContentUnix()
            unstash 'src'
            sh '''
                source /opt/remi/php74/enable
                cmake -Cconfigs/php-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=$(uname -m) \
                      -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.4 \
                      -DCPACK_OUTPUT_FILE_PREFIX=php \
                      -DENABLE_CLANGFORMAT=OFF \
                      -DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF \
                      -Bbuild -H.
                cmake --build build -- -j10
                cd build
                ctest --verbose
                cpack
            '''
            dir('build') {
                archiveArtifacts('php/**')
            }

            clearContentUnix()
            unstash 'src'
            sh '''
                source /opt/remi/php80/enable
                cmake -Cconfigs/php-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=$(uname -m) \
                      -DVIRGIL_PACKAGE_LANGUAGE_VERSION=8.0 \
                      -DCPACK_OUTPUT_FILE_PREFIX=php \
                      -DENABLE_CLANGFORMAT=OFF \
                      -DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF \
                      -Bbuild -H.
                cmake --build build -- -j10
                cd build
                ctest --verbose
                cpack
            '''
            dir('build') {
                archiveArtifacts('php/**')
            }
        }
    }}
}

def build_LangPHP_MacOS(slave, arch) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            def phpVersions = "php php@7.3 php@7.4 php@8.0"

            def optimisationOptions = ""
            def canRunTest = false
            if (arch == "x86_64") {
                optimisationOptions = "-DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF"
                canRunTest = true
            }

            clearContentUnix()
            unstash 'src'
            sh """
                brew unlink ${phpVersions} && brew link php@7.3 --force
                cmake -Cconfigs/php-config.cmake ${optimisationOptions} \
                      -DCMAKE_OSX_ARCHITECTURES=${arch} \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=${arch} \
                      -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.3 \
                      -DCPACK_OUTPUT_FILE_PREFIX=php \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.
                cmake --build build -- -j10
            """
            dir('build') {
                if (canRunTest) {
                    sh "ctest --verbose"
                }
                sh "cpack"
                archiveArtifacts('php/**')
            }

            clearContentUnix()
            unstash 'src'
            sh """
                brew unlink ${phpVersions} && brew link php@7.4 --force
                cmake -Cconfigs/php-config.cmake ${optimisationOptions} \
                      -DCMAKE_OSX_ARCHITECTURES=${arch} \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=${arch} \
                      -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.4 \
                      -DCPACK_OUTPUT_FILE_PREFIX=php \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.
                cmake --build build -- -j10
            """
            dir('build') {
                if (canRunTest) {
                    sh "ctest --verbose"
                }
                sh "cpack"
                archiveArtifacts('php/**')
            }

            clearContentUnix()
            unstash 'src'
            sh """
                brew unlink ${phpVersions} && brew link php@8.0 --force
                cmake -Cconfigs/php-config.cmake ${optimisationOptions} \
                      -DCMAKE_OSX_ARCHITECTURES=${arch} \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=${arch} \
                      -DVIRGIL_PACKAGE_LANGUAGE_VERSION=8.0 \
                      -DCPACK_OUTPUT_FILE_PREFIX=php \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.
                cmake --build build -- -j10
            """
            dir('build') {
                if (canRunTest) {
                    sh "ctest --verbose"
                }
                sh "cpack"
                archiveArtifacts('php/**')
            }
        }
    }}
}

def build_LangPHP_Windows(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace\\${jobPath}") {
            clearContentWindows()
            unstash 'src'
            withEnv(["PHP_HOME=C:\\php-7.3.15",
                     "PHP_DEVEL_HOME=C:\\php-7.3.15-devel"]) {
                bat '''
                    set PATH=%PATH:"=%
                    call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
                    cmake -G"NMake Makefiles" ^
                          -Cconfigs/php-config.cmake ^
                          -DVIRGIL_LIB_PYTHIA=OFF ^
                          -DCMAKE_BUILD_TYPE=Release ^
                          -DVIRGIL_PACKAGE_PLATFORM_ARCH=x86_64 ^
                          -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.3 ^
                          -DCPACK_OUTPUT_FILE_PREFIX=php ^
                          -DENABLE_CLANGFORMAT=OFF ^
                          -Bbuild -H.
                    cmake --build build
                    cd build
                    ctest --verbose
                    cpack
                '''
            }
            dir('build') {
                archiveArtifacts('php/**')
            }

            clearContentWindows()
            unstash 'src'
            withEnv(["PHP_HOME=C:\\php-7.4.3",
                     "PHP_DEVEL_HOME=C:\\php-7.4.3-devel"]) {
                bat '''
                    set PATH=%PATH:"=%
                    call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
                    cmake -G"NMake Makefiles" ^
                          -Cconfigs/php-config.cmake ^
                          -DVIRGIL_LIB_PYTHIA=OFF ^
                          -DCMAKE_BUILD_TYPE=Release ^
                          -DVIRGIL_PACKAGE_PLATFORM_ARCH=x86_64 ^
                          -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.4 ^
                          -DCPACK_OUTPUT_FILE_PREFIX=php ^
                          -DENABLE_CLANGFORMAT=OFF ^
                          -Bbuild -H.
                    cmake --build build
                    cd build
                    ctest --verbose
                    cpack
                '''
            }
            dir('build') {
                archiveArtifacts('php/**')
            }

            clearContentWindows()
            unstash 'src'
            withEnv(["PHP_HOME=C:\\php-8.0.3",
                     "PHP_DEVEL_HOME=C:\\php-8.0.3-devel"]) {
                bat '''
                    set PATH=%PATH:"=%
                    call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
                    cmake -G"NMake Makefiles" ^
                          -Cconfigs/php-config.cmake ^
                          -DVIRGIL_LIB_PYTHIA=OFF ^
                          -DCMAKE_BUILD_TYPE=Release ^
                          -DVIRGIL_PACKAGE_PLATFORM_ARCH=x86_64 ^
                          -DVIRGIL_PACKAGE_LANGUAGE_VERSION=8.0 ^
                          -DCPACK_OUTPUT_FILE_PREFIX=php ^
                          -DENABLE_CLANGFORMAT=OFF ^
                          -Bbuild -H.
                    cmake --build build
                    cd build
                    ctest --verbose
                    cpack
                '''
            }
            dir('build') {
                archiveArtifacts('php/**')
            }
        }
    }}
}

// --------------------------------------------------------------------------
//  Build nodes for language: Java
// --------------------------------------------------------------------------
def build_LangJava_Linux(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            sh '''
                cmake -Cconfigs/java-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/linux" \
                      -DENABLE_CLANGFORMAT=OFF \
                      -DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF \
                      -Bbuild -H.

                cmake --build build --target install -- -j10

                cd wrappers/java
                ./mvnw clean test
            '''
            stash includes: 'wrappers/java/binaries/**', name: 'java_linux'
        }
    }}
}

def build_LangJava_MacOS(slave, arch) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            def optimisationOptions = ""
            def canRunTest = false
            if (arch == "x86_64") {
                optimisationOptions = "-DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF"
                canRunTest = true
            }

            clearContentUnix()
            unstash 'src'
            sh """
                cmake -Cconfigs/java-config.cmake ${optimisationOptions} \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DCMAKE_OSX_ARCHITECTURES=${arch} \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/macos_${arch}" \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.

                cmake --build build --target install -- -j10
            """

            if (canRunTest) {
                dir('wrappers/java') {
                    sh "./mvnw clean test"
                }
            }

            stash includes: 'wrappers/java/binaries/**', name: "java_macos_${arch}"
        }
    }}
}

def build_LangJava_Windows(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace\\${jobPath}") {
            clearContentWindows()
            unstash 'src'
            bat '''
                set PATH=%PATH:"=%
                call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
                cmake -G"NMake Makefiles" ^
                      -Cconfigs/java-config.cmake ^
                      -DVIRGIL_LIB_PYTHIA=OFF ^
                      -DCMAKE_BUILD_TYPE=Release ^
                      -DCMAKE_INSTALL_PREFIX="wrappers\\java\\binaries\\windows" ^
                      -DENABLE_CLANGFORMAT=OFF ^
                      -Bbuild -H.
                cmake --build build --target install

                cd wrappers/java
                mvnw.cmd clean test -P foundation,phe,ratchet
            '''
            stash includes: 'wrappers/java/binaries/**', name: 'java_windows'
        }
    }}
}

def build_LangJava_Android_x86(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            withEnv(['ANDROID_NDK=/Users/virgil/Library/VirgilEnviroment/android-ndk-r19c']) {
                sh '''
                cmake -Cconfigs/java-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DTRANSITIVE_C_FLAGS="-fvisibility=hidden" \
                      -DANDROID_ABI="x86" \
                      -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK}/build/cmake/android.toolchain.cmake" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/android" \
                      -DCMAKE_INSTALL_LIBDIR="lib/x86" \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.

                cmake --build build --target install -- -j10
                '''
            }
            stash includes: 'wrappers/java/binaries/**', name: 'java_android_x86'
        }
    }}
}

def build_LangJava_Android_x86_64(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            withEnv(['ANDROID_NDK=/Users/virgil/Library/VirgilEnviroment/android-ndk-r19c']) {
                sh '''
                cmake -Cconfigs/java-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DTRANSITIVE_C_FLAGS="-fvisibility=hidden" \
                      -DANDROID_ABI="x86_64" \
                      -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK}/build/cmake/android.toolchain.cmake" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/android" \
                      -DCMAKE_INSTALL_LIBDIR="lib/x86_64" \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.

                cmake --build build --target install -- -j10
                '''
            }
            stash includes: 'wrappers/java/binaries/**', name: 'java_android_x86_64'
        }
    }}
}

def build_LangJava_Android_armeabi_v7a(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            withEnv(['ANDROID_NDK=/Users/virgil/Library/VirgilEnviroment/android-ndk-r19c']) {
                sh '''
                cmake -Cconfigs/java-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DTRANSITIVE_C_FLAGS="-fvisibility=hidden" \
                      -DANDROID_ABI="armeabi-v7a" \
                      -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK}/build/cmake/android.toolchain.cmake" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/android" \
                      -DCMAKE_INSTALL_LIBDIR="lib/armeabi-v7a" \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.

                cmake --build build --target install -- -j10
                '''
            }
            stash includes: 'wrappers/java/binaries/**', name: 'java_android_armeabi_v7a'
        }
    }}
}

def build_LangJava_Android_arm64_v8a(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            withEnv(['ANDROID_NDK=/Users/virgil/Library/VirgilEnviroment/android-ndk-r19c']) {
                sh '''
                cmake -Cconfigs/java-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DTRANSITIVE_C_FLAGS="-fvisibility=hidden" \
                      -DANDROID_ABI="arm64-v8a" \
                      -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK}/build/cmake/android.toolchain.cmake" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/android" \
                      -DCMAKE_INSTALL_LIBDIR="lib/arm64-v8a" \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.

                cmake --build build --target install -- -j10
                '''
            }
            stash includes: 'wrappers/java/binaries/**', name: 'java_android_arm64_v8a'
        }
    }}
}

// --------------------------------------------------------------------------
//  Build nodes for language: Python
// --------------------------------------------------------------------------
def build_LangPython_Linux(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            sh '''
                cmake -Cconfigs/python-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DCMAKE_INSTALL_PREFIX="wrappers/python/virgil_crypto_lib" \
                      -DCMAKE_INSTALL_LIBDIR=_libs \
                      -DENABLE_CLANGFORMAT=OFF \
                      -DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF \
                      -Bbuild -H.
                cmake --build build --target install -- -j10

                cd wrappers/python
                python -m unittest discover -s virgil_crypto_lib/tests -p "*_test.py"
            '''
            stash includes: 'wrappers/python/**', excludes: 'dist/**, build/**', name: 'python_wrapper_linux_x86_64'
            stash includes: 'wrappers/python/**', excludes: 'dist/**, build/**', name: 'python_wrapper_linux_x86'
        }
    }}
}

def build_LangPython_MacOS(slave, arch) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            def optimisationOptions = ""
            def canRunTest = false
            if (arch == "x86_64") {
                optimisationOptions = "-DED25519_AMD64_RADIX_64_24K=ON -DED25519_REF10=OFF"
                canRunTest = true
            }

            clearContentUnix()
            unstash 'src'
            sh '''
                cmake -Cconfigs/python-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/python/virgil_crypto_lib" \
                      -DCMAKE_INSTALL_LIBDIR=_libs \
                      -DENABLE_CLANGFORMAT=OFF \
                      -Bbuild -H.
                cmake --build build --target install -- -j10
            '''
            dir('wrappers/python') {
                if (canRunTest) {
                    sh 'python -m unittest discover -s virgil_crypto_lib/tests -p "*_test.py"'
                }
            }

            stash includes: 'wrappers/python/**', excludes: 'dist/**, build/**', name: "python_wrapper_macos_${arch}"
        }
    }}
}

def build_LangPython_Windows(slave, arch) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace\\${jobPath}") {
            def toolchainConfig = ""
            if (arch == "x86_64") {
                toolchainConfig = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
            } else {
                toolchainConfig = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars32.bat"
            }

            clearContentWindows()
            unstash 'src'
            bat """
                set PATH=%PATH:"=%
                call "${toolchainConfig}"
                cmake -G\"NMake Makefiles\" ^
                      -Cconfigs/python-config.cmake ^
                      -DVIRGIL_LIB_PYTHIA=OFF ^
                      -DCMAKE_BUILD_TYPE=Release ^
                      -DCMAKE_INSTALL_PREFIX=\"wrappers\\python\\virgil_crypto_lib\" ^
                      -DCMAKE_INSTALL_LIBDIR=_libs ^
                      -DCMAKE_INSTALL_BINDIR=_libs ^
                      -DENABLE_CLANGFORMAT=OFF ^
                      -Bbuild -H.
                cmake --build build --target install

                rmdir wrappers\\python\\virgil_crypto_lib\\pythia /s /q
            """
            withEnv(["PATH=C:\\Python36_x64;${env.PATH}"]) {
                bat 'cd wrappers\\python && python -m unittest discover -s virgil_crypto_lib/tests -p "*_test.py"'
            }
            stash includes: 'wrappers/python/**', excludes: 'dist/**, build/**', name: "python_wrapper_windows_${arch}"
        }
    }}
}

// --------------------------------------------------------------------------
//  Packaging & Testing
// --------------------------------------------------------------------------
def buildPythonPackages(platform, bdistPlatformName) {
    return { node("build-docker") {
        stage('Build Python packages') {
            echo "DISABLE_PYTHON_BUILDS = ${params.DISABLE_PYTHON_BUILDS}"
            if (params.DISABLE_PYTHON_BUILDS) {
                echo "Skipped due to the false parameter: DISABLE_PYTHON_BUILDS"
                return
            }

            unstash "python_wrapper_${platform}"

            dir('wrappers/python') {
                docker.image("python:2.7").inside("--user root") {
                    sh "pip install wheel"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_egg --plat-name ${bdistPlatformName}"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_wheel --plat-name ${bdistPlatformName}"
                }

                docker.image("python:3.4").inside("--user root") {
                    sh "pip install wheel"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_egg --plat-name ${bdistPlatformName}"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_wheel --plat-name ${bdistPlatformName}"
                }

                docker.image("python:3.5").inside("--user root") {
                    sh "pip install wheel"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_egg --plat-name ${bdistPlatformName}"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_wheel --plat-name ${bdistPlatformName}"
                }

                docker.image("python:3.6").inside("--user root") {
                    sh "pip install wheel"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_egg --plat-name ${bdistPlatformName}"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_wheel --plat-name ${bdistPlatformName}"
                }

                docker.image("python:3.7").inside("--user root") {
                    sh "pip install wheel"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_egg --plat-name ${bdistPlatformName}"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_wheel --plat-name ${bdistPlatformName}"
                }

                docker.image("python:3.8").inside("--user root") {
                    sh "pip install wheel"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_egg --plat-name ${bdistPlatformName}"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_wheel --plat-name ${bdistPlatformName}"
                }

                docker.image("python:3.9").inside("--user root") {
                    sh "pip install wheel"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_egg --plat-name ${bdistPlatformName}"
                    cleanPythonBuildDirectoriesLinux()
                    sh "python setup.py bdist_wheel --plat-name ${bdistPlatformName}"
                }
            }

            //
            // Fixing Python ABI tag.
            // Note, previously was used for Windows and macOS only.
            //
            docker.image("python:2.7").inside("--user root") {
                sh 'for file in wrappers/python/dist/*-cp27mu-*.whl; do echo $file | mv $file $(sed -r \'s/cp27mu/cp27m/g\'); done'
            }

            stash includes: 'wrappers/python/dist/**', name: "python_${platform}"
        }
    }}
}

def testAndroidArtifacts() {
    return { node('build-os-x') {
        stage('Test Android artifacts') {
            echo "RUN_ANDROID_TESTS = ${params.RUN_ANDROID_TESTS}"
            echo "DEPLOY_ANDROID_ARTIFACTS = ${params.DEPLOY_ANDROID_ARTIFACTS}"
            if (!params.RUN_ANDROID_TESTS && !params.DEPLOY_ANDROID_ARTIFACTS) {
                echo "Skipped due to the false parameter: RUN_ANDROID_TESTS"
                return
            }
            clearContentUnix()
            unstash "src"
            unstash "java_android_x86"
            unstash "java_android_x86_64"
            unstash "java_android_armeabi_v7a"
            unstash "java_android_arm64_v8a"

            withEnv(['ANDROID_HOME=/Users/virgil/Library/VirgilEnviroment/android-sdk']) {
                sh '''
                    export PATH=$ANDROID_HOME/emulator:$ANDROID_HOME/tools:$ANDROID_HOME/tools/bin:$ANDROID_HOME/platform-tools:$PATH
                    adb devices | grep emulator | cut -f1 | while read line; do adb -s $line emu kill; done
                '''
                sh '''
                    export PATH=$ANDROID_HOME/emulator:$ANDROID_HOME/tools:$ANDROID_HOME/tools/bin:$ANDROID_HOME/platform-tools:$PATH
                    emulator -avd test_x86_64 -netdelay none -netspeed full -no-window -no-audio -gpu off &
                    android-wait-for-emulator.sh
                    cd wrappers/java/android
                    ./gradlew clean connectedAndroidTest
                    adb devices | grep emulator | cut -f1 | while read line; do adb -s $line emu kill; done
                '''
                sh '''
                    export PATH=$ANDROID_HOME/emulator:$ANDROID_HOME/tools:$ANDROID_HOME/tools/bin:$ANDROID_HOME/platform-tools:$PATH
                    emulator -avd test_x86 -netdelay none -netspeed full -no-window -no-audio -gpu off &
                    android-wait-for-emulator.sh
                    cd wrappers/java/android
                    ./gradlew clean connectedAndroidTest
                    adb devices | grep emulator | cut -f1 | while read line; do adb -s $line emu kill; done
                '''
                sh '''
                    export PATH=$ANDROID_HOME/emulator:$ANDROID_HOME/tools:$ANDROID_HOME/tools/bin:$ANDROID_HOME/platform-tools:$PATH
                    emulator -avd test_v7a -netdelay none -netspeed full -no-window -no-audio -gpu off &
                    android-wait-for-emulator.sh
                    cd wrappers/java/android
                    ./gradlew clean connectedAndroidTest
                    adb devices | grep emulator | cut -f1 | while read line; do adb -s $line emu kill; done
                '''
            }
        }
    }}
}

def packaging_and_testing_nodes = [:]
packaging_and_testing_nodes['build-python-packages-linux-x86'] = buildPythonPackages('linux_x86', 'manylinux1_i686')
packaging_and_testing_nodes['build-python-packages-linux-x86_64'] = buildPythonPackages('linux_x86_64', 'manylinux1_x86_64')
packaging_and_testing_nodes['build-python-packages-macos-x86_64'] = buildPythonPackages('macos_x86_64', 'macosx_10_12_intel')
packaging_and_testing_nodes['build-python-packages-macos-arm64'] = buildPythonPackages('macos_arm64', 'macosx_11_2_arm64')
packaging_and_testing_nodes['build-python-packages-win-x86'] = buildPythonPackages('windows_x86_64', 'win_amd64')
packaging_and_testing_nodes['build-python-packages-win-x86_64'] = buildPythonPackages('windows_x86', 'win32')
packaging_and_testing_nodes['test-android-artifacts'] = testAndroidArtifacts()
parallel(packaging_and_testing_nodes)

// --------------------------------------------------------------------------
//  Deploy
// --------------------------------------------------------------------------
def calculateArtifactsChecksum() {
    return { node('master') { stage('Calculate Checksum') {
        def branchSubPath =  env.BRANCH_NAME ? '/branches/' + env.BRANCH_NAME : ''
        def shortJobName = env.BRANCH_NAME ? env.JOB_NAME.replace('/' + env.BRANCH_NAME, '') : env.JOB_NAME
        def artifactsDir =
                env.JENKINS_HOME + '/jobs/' + shortJobName + branchSubPath + '/builds/' + env.BUILD_NUMBER + '/archive'
        dir(artifactsDir) {
            sh 'find . -type f -name "virgil-crypto-c-*" -exec sh -c "sha256sum {} | cut -d\' \' -f1-1 > {}.sha256" \\;'
        }
    }}}
}


def deployJavaArtifacts() {
    return {
        node('master') {
            stage('Deploy Java artifacts') {
                echo "DEPLOY_JAVA_ARTIFACTS = ${params.DEPLOY_JAVA_ARTIFACTS}"
                if (!params.DEPLOY_JAVA_ARTIFACTS) {
                    echo "Skipped due to the false parameter: DEPLOY_JAVA_ARTIFACTS"
                    return
                }
                clearContentUnix()
                unstash "src"
                unstash "java_linux"
                unstash "java_macos_x86_64"
                unstash "java_macos_arm64"
                unstash "java_windows"

                sh """
                    env
                    cd wrappers/java
                    ./mvnw clean deploy -P foundation,phe,pythia,ratchet,release -Dgpg.keyname=${params.gpg_keyname}
                """
            }
        }
    }
}

def deployAndroidArtifacts() {
    return {
        node('master') {
            stage('Deploy Android artifacts') {
                echo "DEPLOY_ANDROID_ARTIFACTS = ${params.DEPLOY_ANDROID_ARTIFACTS}"
                if (!params.DEPLOY_ANDROID_ARTIFACTS) {
                    echo "Skipped due to the false parameter: DEPLOY_ANDROID_ARTIFACTS"
                    return
                }
                clearContentUnix()
                unstash "src"
                unstash "java_android_x86"
                unstash "java_android_x86_64"
                unstash "java_android_armeabi_v7a"
                unstash "java_android_arm64_v8a"

                withEnv(['ANDROID_HOME=/srv/apps/android-sdk']) {
                    sh '''
                        env
                        cd wrappers/java/android
                        ./gradlew clean publish \
                            -Dhttp.socketTimeout=60000 -Dhttp.connectionTimeout=60000 \
                            -Dorg.gradle.internal.http.socketTimeout=60000 -Dorg.gradle.internal.http.connectionTimeout=60000
                    '''
                }
            }
        }
    }
}

def deployPythonArtifacts() {
    return {
        node('master') {
            stage('Deploy Python artifacts') {
                echo "DISABLE_PYTHON_BUILDS = ${params.DISABLE_PYTHON_BUILDS}"
                if (params.DISABLE_PYTHON_BUILDS) {
                    echo "Skipped due to the false parameter: DISABLE_PYTHON_BUILDS"
                    return
                }

                echo "DEPLOY_PYTHON_ARTIFACTS = ${params.DEPLOY_PYTHON_ARTIFACTS}"
                if (!params.DEPLOY_PYTHON_ARTIFACTS) {
                    echo "Skipped due to the false parameter: DEPLOY_PYTHON_ARTIFACTS"
                    return
                }
                clearContentUnix()
                unstash "python_linux_x86"
                unstash "python_linux_x86_64"
                unstash "python_macos_x86_64"
                unstash "python_macos_arm64"
                unstash "python_windows_x86"
                unstash "python_windows_x86_64"

                sh "cp -r wrappers/python/dist wrappers/python/python"

                dir('wrappers/python'){
                    archiveArtifacts('python/**')
                }

                sh """
                    env
                    cd wrappers/python
                    twine upload dist/*
                """
            }
        }
    }
}


def deploy_nodes = [:]
deploy_nodes['calculate-artifacts-checksum'] = calculateArtifactsChecksum()
deploy_nodes['deploy-java-artifacts'] = deployJavaArtifacts()
deploy_nodes['deploy-android-artifacts'] = deployAndroidArtifacts()
deploy_nodes['deploy-python-artifacts'] = deployPythonArtifacts()
parallel(deploy_nodes)
