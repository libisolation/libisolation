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
      make test ARGS=-V
    '''
}
