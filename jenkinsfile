pipeline {
    agent any
      parameters {
        // Parameter to input a custom version
        string(name: 'VERSION', defaultValue: '', description: 'Version to deploy on production')

        // Parameter to choose a version from predefined options
        choice(name: 'VERSION_CHOICE', choices: ['1.1.0', '1.2.0', '1.3.0'], description: 'Select version to deploy')

        // Boolean parameter to decide whether to execute tests
        booleanParam(name: 'executeTests', defaultValue: true, description: 'Execute tests during the pipeline?')
    }
    environment {
        JAVA_VERSION = '11'
        MAVEN_VERSION = '3.8.5'
    }
    stages {
        stage('Build') {
            steps {
                echo 'Building...'
                echo "Using Java version: ${env.JAVA_VERSION}"
                echo "Using Maven version: ${env.MAVEN_VERSION}"
                // Compile the project
                bat 'nvm install'
            }
        }
        stage('Test') {
            when {
                expression { return params.executeTests } // Run tests only if the parameter is true
            }
            steps {
                echo 'Running Tests...'
                echo "Testing with Java version: ${env.JAVA_VERSION}"
                // Run the test cases
                // sh 'mvn test'
            }
        }
        stage('Deploy') {
            steps {
                echo 'Deploying...'
                // Placeholder for deployment-specific commands
            }
        }
    }
    post {
        always {
            echo 'Pipeline execution completed.'
        }
        success {
            echo 'Build and tests succeeded!'
        }
        failure {
            echo 'Build or tests failed. Please check the logs.'
        }
    }
}
