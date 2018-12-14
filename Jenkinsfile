#!groovy

// --------------------------------------------------------------------------
stage 'Grab SCM'
// --------------------------------------------------------------------------

node('master') {
    clearContentUnix()
    checkout scm
    stash includes: '**', name: 'src'
}

// --------------------------------------------------------------------------
stage 'Build'
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
nodes['lang-c-platform-win8-mingw64'] = build_LangC_Windows_MinGW('build-win8')

//
//  Language: PHP
//
nodes['lang-php-platform-linux'] = build_LangPHP_Linux('build-centos7')

parallel nodes


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


// --------------------------------------------------------------------------
//  Build nodes for language: C
// --------------------------------------------------------------------------
def build_LangC_Unix(slave) {
    return { node(slave) {
        clearContentUnix()
        unstash 'src'
        sh 'mkdir build'
        dir('build') {
            sh 'cmake -DVIRGIL_PACKAGE_PLATFORM_ARCH=$(uname -m) ..'
            sh 'make -j10'
            sh 'cpack'
            archiveArtifacts('packages/**')
        }
    }}
}

def build_LangC_Windows_MinGW(slave) {
    return { node(slave) {
        clearContentWindows()
        unstash 'src'
        withEnv(["PATH=C:\\Program Files\\mingw-w64\\x86_64-8.1.0-win32-seh-rt_v6-rev0\\mingw64\\bin;${env.PATH}"]) {
            bat 'echo %PATH%'
            bat 'cmake -G"MinGW Makefiles" -DVIRGIL_PACKAGE_PLATFORM_ARCH=x86_64 -Bbuild -H.'
            bat 'cmake --build build -- -j10'
        }
        dir('build') {
            bat 'cpack'
            archiveArtifacts('packages/**')
        }
    }}
}

// --------------------------------------------------------------------------
//  Build nodes for language: PHP
// --------------------------------------------------------------------------
def build_LangPHP_Linux(slave) {
    return { node(slave) {
        clearContentUnix()
        unstash 'src'
        sh '''
            source /opt/remi/php72/enable
            cmake -DVIRGIL_PACKAGE_PLATFORM_ARCH=$(uname -m) \
                  -DVIRGIL_WRAP_PHP=ON \
                  -DVIRGIL_INSTALL_WRAP_SRCS=ON \
                  -DVIRGIL_INSTALL_WRAP_LIBS=ON \
                  -DVIRGIL_INSTALL_WRAP_DEPS=ON \
                  -DVIRGIL_C_TESTING=OFF \
                  -DVIRGIL_LIB_RATCHET=OFF \
                  -DVIRGIL_LIB_PYTHIA=OFF \
                  -DVIRGIL_INSTALL_CMAKE=OFF \
                  -DVIRGIL_INSTALL_DEPS_CMAKE=OFF \
                  -DVIRGIL_INSTALL_DEPS_HDRS=OFF \
                  -DVIRGIL_INSTALL_DEPS_LIBS=OFF \
                  -DVIRGIL_INSTALL_HDRS=OFF \
                  -DVIRGIL_INSTALL_LIBS=OFF \
                  -Bbuild -H.
            cmake --build build -- -j10
            cd build
            cpack
        '''
        dir('build') {
            archiveArtifacts('packages/**')
        }
    }}
}
