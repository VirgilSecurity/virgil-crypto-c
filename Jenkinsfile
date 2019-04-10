#!groovy


// --------------------------------------------------------------------------
//  Grab SCM
// --------------------------------------------------------------------------

node('master') {
    stage('Grab SCM') {
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
nodes['lang-c-platform-linux'] = build_LangC_Unix('build-centos7')
nodes['lang-c-platform-macos'] = build_LangC_Unix('build-os-x')
nodes['lang-c-platform-windows'] = build_LangC_Windows('build-win8')

//
//  Language: PHP
//
nodes['lang-php-platform-linux'] = build_LangPHP_Linux('build-centos7')
nodes['lang-php-platform-macos'] = build_LangPHP_MacOS('build-os-x')
nodes['lang-php-platform-windows'] = build_LangPHP_Windows('build-win8')

//
//  Language: Java
//
nodes['lang-java-platform-linux'] = build_LangJava_Linux('build-centos7')
nodes['lang-java-platform-macos'] = build_LangJava_MacOS('build-os-x')
nodes['lang-java-platform-windows'] = build_LangJava_Windows('build-win8')
nodes['lang-java-platform-android-x86'] = build_LangJava_Android_x86('build-os-x')
nodes['lang-java-platform-android-x86_64'] = build_LangJava_Android_x86_64('build-os-x')
nodes['lang-java-platform-android-armeabi-v7a'] = build_LangJava_Android_armeabi_v7a('build-os-x')
nodes['lang-java-platform-android-arm64-v8a'] = build_LangJava_Android_arm64_v8a('build-os-x')

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

// --------------------------------------------------------------------------
//  Build nodes for language: C
// --------------------------------------------------------------------------
def build_LangC_Unix(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            sh '''
                cmake -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=$(uname -m) \
                      -DCPACK_OUTPUT_FILE_PREFIX=c \
                      -Bbuild -H.
                cmake --build build -- -j10
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
                source /opt/remi/php72/enable
                cmake -Cconfigs/php-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=$(uname -m) \
                      -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.2 \
                      -DCPACK_OUTPUT_FILE_PREFIX=php \
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

def build_LangPHP_MacOS(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            def phpVersions = "php56 php70 php71 php72"
            sh '''
                brew unlink ${phpVersions} && brew link php72 --force
                cmake -Cconfigs/php-config.cmake \
                      -DCMAKE_BUILD_TYPE=Release \
                      -DVIRGIL_PACKAGE_PLATFORM_ARCH=$(uname -m) \
                      -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.2 \
                      -DCPACK_OUTPUT_FILE_PREFIX=php \
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

def build_LangPHP_Windows(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace\\${jobPath}") {
            clearContentWindows()
            unstash 'src'
            withEnv(["PHP_HOME=C:\\php-7.2.6",
                     "PHP_DEVEL_HOME=C:\\php-7.2.6-devel",\
                     "PHPUNIT_HOME=C:\\phpunit-7.2.4"]) {
                bat '''
                    set PATH=%PATH:"=%
                    call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
                    cmake -G"NMake Makefiles" ^
                          -Cconfigs/php-config.cmake ^
                          -DCMAKE_BUILD_TYPE=Release ^
                          -DVIRGIL_PACKAGE_PLATFORM_ARCH=x86_64 ^
                          -DVIRGIL_PACKAGE_LANGUAGE_VERSION=7.2 ^
                          -DCPACK_OUTPUT_FILE_PREFIX=php ^
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
                cmake -DCMAKE_BUILD_TYPE=Release \
                      -Cconfigs/java-config.cmake \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/linux" \
                      -Bbuild -H.

                cmake --build build --target install -- -j10

                cd wrappers/java
                ./mvnw clean test
            '''
            stash includes: 'wrappers/java/binaries/**', name: 'java_linux'
        }
    }}
}

def build_LangJava_MacOS(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace/${jobPath}") {
            clearContentUnix()
            unstash 'src'
            sh '''
                cmake -DCMAKE_BUILD_TYPE=Release \
                      -Cconfigs/java-config.cmake \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/macos" \
                      -Bbuild -H.

                cmake --build build --target install -- -j10

                cd wrappers/java
                ./mvnw clean test
            '''
            stash includes: 'wrappers/java/binaries/**', name: 'java_macos'
        }
    }}
}

def build_LangJava_Windows(slave) {
    return { node(slave) {
        def jobPath = pathFromJobName(env.JOB_NAME)
        ws("workspace\\${jobPath}") {
            clearContentWindows()
            unstash 'src'
            withEnv([]) {
                bat '''
                    set PATH=%PATH:"=%
                    call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
                    cmake -G"NMake Makefiles" ^
                          -Cconfigs/java-config.cmake ^
                          -DVIRGIL_LIB_PYTHIA=OFF ^
                          -DCMAKE_BUILD_TYPE=Release ^
                          -DCMAKE_INSTALL_PREFIX="wrappers\\java\\binaries\\windows" ^
                          -Bbuild -H.
                    cmake --build build --target install

                    cd wrappers/java
                    mvnw.cmd clean test -P foundation,phe,ratchet
                '''
            }
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
                      -DANDROID_ABI="x86" \
                      -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK}/build/cmake/android.toolchain.cmake" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/android" \
                      -DCMAKE_INSTALL_LIBDIR="lib/x86" \
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
                      -DANDROID_ABI="x86_64" \
                      -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK}/build/cmake/android.toolchain.cmake" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/android" \
                      -DCMAKE_INSTALL_LIBDIR="lib/x86_64" \
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
                      -DANDROID_ABI="armeabi-v7a" \
                      -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK}/build/cmake/android.toolchain.cmake" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/android" \
                      -DCMAKE_INSTALL_LIBDIR="lib/armeabi-v7a" \
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
                      -DANDROID_ABI="arm64-v8a" \
                      -DCMAKE_TOOLCHAIN_FILE="${ANDROID_NDK}/build/cmake/android.toolchain.cmake" \
                      -DCMAKE_INSTALL_PREFIX="wrappers/java/binaries/android" \
                      -DCMAKE_INSTALL_LIBDIR="lib/arm64-v8a" \
                      -Bbuild -H.

                cmake --build build --target install -- -j10
                '''
            }
            stash includes: 'wrappers/java/binaries/**', name: 'java_android_arm64_v8a'
        }
    }}
}


// --------------------------------------------------------------------------
//  Calculate Checksum
// --------------------------------------------------------------------------

node('master') {
    stage('Calculate Checksum') {
        def branchSubPath =  env.BRANCH_NAME ? '/branches/' + env.BRANCH_NAME : ''
        def shortJobName = env.BRANCH_NAME ? env.JOB_NAME.replace('/' + env.BRANCH_NAME, '') : env.JOB_NAME
        def artifactsDir =
                env.JENKINS_HOME + '/jobs/' + shortJobName + branchSubPath + '/builds/' + env.BUILD_NUMBER + '/archive'
        dir(artifactsDir) {
            sh 'find . -type f -name "virgil-crypto-c-*" -exec sh -c "sha256sum {} | cut -d\' \' -f1-1 > {}.sha256" \\;'
        }
    }
}

// --------------------------------------------------------------------------
//  Build and deploy Java libraries
// --------------------------------------------------------------------------
node('master') {
    stage('Build and deploy Java libraries') {
        unstash "java_linux"
        unstash "java_macos"
        unstash "java_windows"

        sh """
            pwd
            source /var/lib/jenkins/.bashrc
            env
            cd wrappers/java
            ./mvnw clean deploy -P foundation,phe,pythia,ratchet,release -Dgpg.keyname=${gpg_keyname}
        """
    }
}
