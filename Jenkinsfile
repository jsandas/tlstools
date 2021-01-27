// Jenkins pipeline for tlstools project
pipeline {

    // agent defines where the pipeline will run.
    agent {
        node {
            label "linux-slaves"
            customWorkspace "/usr/local/jenkins/workspace/tlstools_${BRANCH_NAME}"
        }
    }

    // The options directive is for configuration that applies to the whole job.
    options {
        // For example, we'd like to make sure we only keep 10 builds at a time, so
        // we don't fill up our storage!
        buildDiscarder(logRotator(numToKeepStr: '3'))

        // And we'd really like to be sure that this build doesn't hang forever, so
        // let's time it out after a while.
        timeout(time: 10, unit: 'MINUTES')

        // Don't checkout automatically because Jenkins sucks at checking out
        skipDefaultCheckout()
    }

    triggers {
        // When webhooks are working, remove this!
        pollSCM('*/15 * * * *')
    }

    stages {
        stage("Checking out code") {
            steps {
                checkout scm
                sshagent(['5cc1672c-ed15-42ef-98ac-147656523e48']) {
                    sh """
                        git remote set-url origin git@github.com:jsandas/tlstools.git
                        git config --add remote.origin.fetch +refs/heads/master:refs/remotes/origin/master
                    """
                    sh "git fetch --all && git merge origin/master"
                }
            }
        }

        stage("Build application with tests") {
            environment {
                SHORTCOMMIT=sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
            }
            steps {
                sh "docker build --pull --rm --target=build -t tlstools-build:$SHORTCOMMIT ."
                sh "docker run --rm -v $WORKSPACE:/src/tlstools -e CGO_ENABLED=0 tlstools-build:$SHORTCOMMIT ./run_unit_tests.sh -cov"
            }
        }

        stage("Push Sonar Reports") {
            when {
                not {
                    branch 'master'
                }
            }
            environment {
                PR_NUM=env.BRANCH_NAME.replace('PR-','')
            }
            steps {
                script {
                    if (env.CHANGE_ID == null) {
                        sh "docker run -v \"$WORKSPACE:/opt/project\" jsandas/sonar-scanner -Dsonar.branch.name=$BRANCH_NAME"
                    } else {
                        sh "docker run -v \"$WORKSPACE:/opt/project\" jsandas/sonar-scanner -Dsonar.pullrequest.key=$PR_NUM -Dsonar.pullrequest.branch=$CHANGE_BRANCH -Dsonar.pullrequest.base=$CHANGE_TARGET"
                    }
                }
            }
        }

        stage("Push Sonar Reports for master") {
            when {
                branch 'master'
            }
            steps {
                sh "docker run -v \"$WORKSPACE:/opt/project\" jsandas/sonar-scanner"
            }
        }

        stage("Build Docker containers") {
            environment {
                SHORTCOMMIT=sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
            }
            steps {
                sh 'docker build --pull --rm -t $DEV_DOCKER_REGISTRY/tlstools:$SHORTCOMMIT -t $DEV_DOCKER_REGISTRY/tlstools:latest .'
            }
        }

        stage("Acceptance Tests") {
            when { changeRequest() }
            environment {
                SHORTCOMMIT=sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
            }
            steps {
                script {
                    try {
                        sh 'python run_acceptance_tests.py'
                    }
                    finally {
                        sh '''
                            docker-compose -f acceptance.yml logs tlstools > tlstools_${BRANCH_NAME}.log
                        '''
                        archiveArtifacts artifacts: 'tlstools_${BRANCH_NAME}.log', allowEmptyArchive: true
                    }
                }
            }
        }

        stage("Publish latest images to registry") {
            when {
                // Only publish the docker image if the branch is master
                branch 'master'
            }
            environment {
                SHORTCOMMIT=sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'dev-nexus-credentials', passwordVariable: 'dockerPassword', usernameVariable: 'dockerUser')]) {
                    // Tag and push the master "merge" commit to the Docker registry
                    sh '''
                    echo $dockerPassword | docker login $DEV_DOCKER_REGISTRY -u $dockerUser --password-stdin
                    docker push $DEV_DOCKER_REGISTRY/tlstools:$SHORTCOMMIT
                    '''
                    // Tag and push the master commit as "latest" to the Docker registry
                    sh '''
                    docker push $DEV_DOCKER_REGISTRY/tlstools:latest
                    docker logout $DEV_DOCKER_REGISTRY
                    '''
                }

                withCredentials([string(credentialsId: '59e9b612-4496-4924-8619-b94a236b3b76', variable: 'slackCredentials')]) {
                    slackSend token: slackCredentials, channel: "deploy-builds", message: "tlstools build finished: \n" + 
                        "${DEV_DOCKER_REGISTRY}/tlstools:${SHORTCOMMIT}"
                }
            }
        }
    }

    post {
        success {
            // #51e043 is green
            script {
                if (env.CHANGE_ID == null) {
                    slackSend color: "#51e043", message: "Success ${env.JOB_NAME} on ${env.NODE_NAME} Branch: ${env.GIT_BRANCH}\n" +
                            "${env.RUN_DISPLAY_URL}"
                } else {
                    slackSend color: "#51e043", message: "Success ${env.JOB_NAME} on ${env.NODE_NAME} Branch: ${env.CHANGE_BRANCH}\n" +
                            "${env.RUN_DISPLAY_URL}\n" +
                            "User: ${env.CHANGE_AUTHOR_DISPLAY_NAME} | Pull Request: ${env.CHANGE_URL}"
                }
            }
        }
        failure {
            // #e04351 is red
            script {
                if (env.CHANGE_ID == null) {
                    slackSend color: "#e04351", message: "Failed ${env.JOB_NAME} on ${env.NODE_NAME} Branch: ${env.GIT_BRANCH}\n" +
                            "${env.RUN_DISPLAY_URL}"
                } else {
                    slackSend color: "#e04351", message: "Failed ${env.JOB_NAME} on ${env.NODE_NAME} Branch: ${env.CHANGE_BRANCH}\n" +
                            "${env.RUN_DISPLAY_URL}\n" +
                            "User: ${env.CHANGE_AUTHOR_DISPLAY_NAME} | Pull Request: ${env.CHANGE_URL}"
                }
            }
        }

        cleanup {
            sh "docker rmi -f \$(docker images | grep tlstools | awk '{print \$3}') || true"
            sh "docker rmi $DEV_DOCKER_REGISTRY/openssl:1.0.2-test"
            sh "docker system prune -f"
            cleanWs()
        }
    }
    
}
