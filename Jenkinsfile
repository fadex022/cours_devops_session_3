pipeline {
    agent any

    environment {
        PROJECT = "fadel" // à modifier avec votre projet
        REPOSITORY = "fastapi-postgres"
        IMAGE = "$PROJECT/$REPOSITORY"
        REGISTRY_HOST = "https://harbor.devgauss.com"
    }

    parameters {
        choice(
            name: 'ENVIRONMENT',
            choices: ['development', 'staging', 'production'],
            description: 'Target environment'
        )
        booleanParam(
            name: 'SKIP_TESTS',
            defaultValue: true,
            description: 'Skip test execution'
        )
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Set up Python') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    python3 -m pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('Run Tests') {
            when {
                expression { return !params.SKIP_TESTS }
            }
            steps {
                withSonarQubeEnv(SonarQube) {
                    sh '''
                    . venv/bin/activate
                    # Install additional test dependencies if needed
                    pip install pytest-xdist

                    # Run tests with JUnit report for better visualization in Jenkins
                    pytest --junitxml=test-results.xml

                    # Run tests with coverage reporting
                    pytest \
                        --cov=. \
                        --cov-report=xml:coverage.xml \
                        --cov-report=html:htmlcov \
                        --cov-report=term \
                        --cov-fail-under=80

                    sonar-scanner
                    '''
                }
            }
            post {
                always {
                    // Archive test artifacts and coverage reports
                    archiveArtifacts artifacts: 'coverage.xml,htmlcov/**/*,test-results.xml', allowEmptyArchive: true

                    // Publish JUnit test results
                    junit 'test-results.xml'

                    // Publish HTML coverage report
                    publishHTML(target: [
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'htmlcov',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                }
            }
        }

        stage('Build and Push Docker Image') {
            when {
                expression {
                    return env.CHANGE_ID == null // Skip for pull requests
                }
            }
            steps {
                script {
                    def image = docker.build("$IMAGE:${env.BUILD_ID}")
                    docker.withRegistry("$REGISTRY_HOST", 'registry-credentials-fadel') { // Créez un credentials de type Username Password avec les accès de votre compte robot Harbor
                        image.push()
                        image.push('latest')
                    }
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo 'Pipeline succeeded!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}












/*
        stage('Code Quality Checks') {
            parallel {
                stage('Lint') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            pip install flake8 black isort

                            # Run linting
                            flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

                            # Check code formatting
                            black --check .

                            # Check import sorting
                            isort --check-only .
                        '''
                    }
                }

                stage('Security Scan') {
                    steps {
                        sh '''
                            . venv/bin/activate
                            pip install bandit safety

                            # Run security checks
                            bandit -r . -x tests/

                            # Check for known vulnerabilities
                            safety check
                        '''
                    }
                }
            }
        }
        */
/*z5WQHoxUsDTh3saibDbaS7Ug0EZbToIk*/

/*TODO */
/* Plugins to block pipeline triggers*/
