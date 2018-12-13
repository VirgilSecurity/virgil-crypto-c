#!groovy

// --------------------------------------------------------------------------
stage 'Grab SCM'

node('master') {
    clearContentUnix()
    checkout scm
    stash includes: '**', name: 'src'
}

// --------------------------------------------------------------------------
stage 'Build'

def nodes = [:]
nodes['lang-c-platform-linux'] = build_LangC_Unix('build-centos7')
nodes['lang-c-platform-macos'] = build_LangC_Unix('build-os-x')
nodes['lang-c-platform-win8-mingw64'] = build_LangC_Windows_MinGW('build-win8')
parallel nodes

def clearContentUnix() {
    sh 'rm -fr -- *'
}

def clearContentWindows() {
    bat "(for /F \"delims=\" %%i in ('dir /b') do (rmdir \"%%i\" /s/q >nul 2>&1 || del \"%%i\" /s/q >nul 2>&1 )) || rem"
}

def archiveArtifacts(pattern) {
    step([$class: 'ArtifactArchiver', artifacts: pattern, fingerprint: true, onlyIfSuccessful: true])
}

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
        withEnv(["PATH=%PROGRAMFILES%\\mingw-w64\\x86_64-8.1.0-win32-seh-rt_v6-rev0\\mingw64\\bin;${env.PATH}"]) {
            bat 'echo %PATH%'
            bat 'cmake -G"MinGW Makefiles" -DVIRGIL_PACKAGE_PLATFORM_ARCH=x86_64 -Bbuild -H.'
            bat 'cmake --build --build'
        }
        dir('build') {
            bat 'cpack'
            archiveArtifacts('packages/**')
        }
    }}
}
