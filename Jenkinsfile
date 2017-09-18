node {
    stage "Clone Repository"
    checkout scm
    sh "git clean -fx"

    stage "Build"
    sh '''mkdir -p build
      cd build
      cmake -DCMAKE_BUILD_TYPE=Release ..
      make
    '''

    stage "Test"
    sh '''cd build
      sg kvm -c "make test ARGS=-V"
    '''
}
