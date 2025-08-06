# Formation DevOps - Session 10
## SonarQube - Intégration CI/CD (2h)

### 📋 Objectifs de la session
À la fin de cette session, vous serez capable de :
- Configurer et comprendre les Quality Gates SonarQube
- Intégrer SonarQube dans des pipelines Jenkins
- Intégrer SonarQube avec GitHub Actions
- Automatiser l'analyse de qualité dans le workflow CI/CD
- Gérer les conventions et politiques qualité
- Résoudre les problèmes d'intégration courants

### 🔄 Rappel Session Précédente

#### 1.1 Concepts Acquis
**Installation SonarQube** : Serveur installé et configuré
**Analyse manuelle** : Première analyse avec SonarQube Scanner
**Métriques qualité** : Compréhension des indicateurs
**Interface web** : Navigation dans les résultats d'analyse

#### 1.2 Limitations de l'Analyse Manuelle
Avec l'analyse manuelle, nous avons des limitations :
- ❌ Processus manuel et répétitif
- ❌ Pas d'automatisation dans le workflow
- ❌ Risque d'oubli d'analyse
- ❌ Pas de blocage automatique sur problèmes qualité

**Solution** : Intégration dans les pipelines CI/CD pour automatiser l'analyse

## 1. Introduction aux Quality Gates

### 1.1 Qu'est-ce qu'un Quality Gate ?

Un **Quality Gate** est un ensemble de conditions de qualité que le code doit respecter pour être considéré comme prêt pour la production.

**Principe** :
```
Code → Analyse SonarQube → Quality Gate → ✅ PASSED / ❌ FAILED
```

**Avantages** :
- 🛡️ **Protection** : Empêche le code de mauvaise qualité d'atteindre la production
- 📊 **Standardisation** : Critères uniformes pour tous les projets
- 🔄 **Automatisation** : Décision automatique basée sur les métriques
- 📈 **Amélioration continue** : Suivi de l'évolution de la qualité

### 1.2 Composition d'un Quality Gate

Un Quality Gate contient plusieurs **conditions** basées sur :

#### Métriques de Couverture
- **Coverage** : Pourcentage de code couvert par les tests
- **New Coverage** : Couverture sur le nouveau code

#### Métriques de Fiabilité
- **Bugs** : Nombre de bugs détectés
- **New Bugs** : Nouveaux bugs introduits

#### Métriques de Sécurité
- **Vulnerabilities** : Vulnérabilités de sécurité
- **Security Hotspots** : Points sensibles de sécurité

#### Métriques de Maintenabilité
- **Code Smells** : Problèmes de maintenabilité
- **Technical Debt** : Dette technique estimée

### 1.3 Configuration des Quality Gates

#### Accès à la Configuration
```
SonarQube → Administration → Quality Gates
```

#### Quality Gate par Défaut
SonarQube fournit un Quality Gate "Sonar way" avec :
- Coverage sur nouveau code > 80%
- Duplicated Lines sur nouveau code < 3%
- Maintenability Rating sur nouveau code = A
- Reliability Rating sur nouveau code = A
- Security Rating sur nouveau code = A

#### Création d'un Quality Gate Personnalisé

**Étape 1 : Créer un nouveau Quality Gate**
```
Quality Gates → Create → Nom: "Company Standards"
```

**Étape 2 : Ajouter des conditions**
```
Add Condition → Sélectionner la métrique → Définir le seuil
```

**Exemple de configuration stricte** :
```
- Coverage (Overall Code) > 85%
- Coverage (New Code) > 90%
- Bugs (Overall Code) = 0
- Vulnerabilities (Overall Code) = 0
- Code Smells (New Code) < 5
- Duplicated Lines (%) (New Code) < 3%
- Maintainability Rating (New Code) = A
```

## 2. Intégration avec Jenkins

### 2.1 Configuration du Plugin SonarQube

#### Installation du Plugin
```
Jenkins → Manage Jenkins → Manage Plugins → Available
Rechercher: "SonarQube Scanner"
Installer et redémarrer Jenkins
```

#### Configuration du Serveur SonarQube
```
Jenkins → Manage Jenkins → Configure System
Section "SonarQube servers":
- Name: SonarQube
- Server URL: http://localhost:9000
- Server authentication token: [Token généré dans SonarQube]
```

#### Configuration de l'Outil Scanner
```
Jenkins → Manage Jenkins → Global Tool Configuration
Section "SonarQube Scanner":
- Name: SonarQube Scanner
- Install automatically: ✅
- Version: Latest
```

### 2.2 Pipeline Jenkins avec SonarQube

#### Pipeline Déclaratif Simple
```groovy
pipeline {
    agent any
    
    environment {
        PROJECT = "fastapi-postgres"
        SONAR_TOKEN = credentials('sonarqube-token')
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
            steps {
                sh '''
                    . venv/bin/activate
                    # Run tests with JUnit report
                    pytest --junitxml=test-results.xml
                    
                    # Run tests with coverage reporting
                    pytest \
                        --cov=. \
                        --cov-report=xml:coverage.xml \
                        --cov-report=html:htmlcov \
                        --cov-report=term \
                        --cov-fail-under=80
                '''
            }
            post {
                always {
                    junit 'test-results.xml'
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
        
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh '''
                        sonar-scanner \
                        -Dsonar.projectKey=fastapi-postgres \
                        -Dsonar.projectName="FastAPI PostgreSQL Application" \
                        -Dsonar.projectVersion=1.0 \
                        -Dsonar.sources=. \
                        -Dsonar.python.coverage.reportPaths=coverage.xml \
                        -Dsonar.python.xunit.reportPaths=test-results.xml \
                        -Dsonar.exclusions=venv/**,tests/**,**/__pycache__/**,*.pyc
                    '''
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
        
        stage('Build and Push Docker Image') {
            when {
                branch 'main'
            }
            steps {
                script {
                    def image = docker.build("fastapi-postgres:${env.BUILD_ID}")
                    docker.withRegistry('https://harbor.devgauss.com', 'registry-credentials') {
                        image.push()
                        image.push('latest')
                    }
                }
            }
        }
    }
    
    post {
        failure {
            emailext to: 'team@company.com',
                     subject: "Pipeline Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                     body: "Quality Gate or build failed. Check console output."
        }
        always {
            cleanWs()
        }
    }
}
```

#### Pipeline avec Analyse Différentielle (Pull Request)
```groovy
pipeline {
    agent any
    
    environment {
        SONAR_TOKEN = credentials('sonarqube-token')
        GITHUB_TOKEN = credentials('github-token')
    }
    
    stages {
        stage('Checkout') {
            steps {
                script {
                    if (env.CHANGE_ID) {
                        // Pull Request
                        checkout([
                            $class: 'GitSCM',
                            branches: [[name: "origin/pr/${env.CHANGE_ID}/merge"]],
                            userRemoteConfigs: [[
                                url: 'https://github.com/user/fastapi-postgres.git',
                                refspec: "+refs/pull/${env.CHANGE_ID}/head:refs/remotes/origin/pr/${env.CHANGE_ID}/head"
                            ]]
                        ])
                    } else {
                        // Branch normale
                        git branch: env.BRANCH_NAME, url: 'https://github.com/user/fastapi-postgres.git'
                    }
                }
            }
        }
        
        stage('Set up Python') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install -r requirements.txt
                    pip install pytest pytest-cov
                '''
            }
        }
        
        stage('Run Tests') {
            steps {
                sh '''
                    . venv/bin/activate
                    pytest --junitxml=test-results.xml
                    pytest --cov=. --cov-report=xml:coverage.xml
                '''
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    script {
                        def scannerArgs = """
                            -Dsonar.projectKey=fastapi-postgres \
                            -Dsonar.projectName="FastAPI PostgreSQL Application" \
                            -Dsonar.sources=. \
                            -Dsonar.python.coverage.reportPaths=coverage.xml \
                            -Dsonar.python.xunit.reportPaths=test-results.xml \
                            -Dsonar.exclusions=venv/**,tests/**,**/__pycache__/**,*.pyc
                        """
                        
                        if (env.CHANGE_ID) {
                            // Analyse Pull Request
                            scannerArgs += """
                                -Dsonar.pullrequest.key=${env.CHANGE_ID} \
                                -Dsonar.pullrequest.branch=${env.CHANGE_BRANCH} \
                                -Dsonar.pullrequest.base=${env.CHANGE_TARGET} \
                                -Dsonar.pullrequest.provider=github \
                                -Dsonar.pullrequest.github.repository=user/fastapi-postgres
                            """
                        } else {
                            // Analyse branche
                            scannerArgs += "-Dsonar.branch.name=${env.BRANCH_NAME}"
                        }
                        
                        sh "sonar-scanner ${scannerArgs}"
                    }
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }
    }
}
```

### 2.3 Configuration Avancée

#### Webhook SonarQube vers Jenkins
Pour accélérer le retour du Quality Gate :

**Dans SonarQube** :
```
Administration → Configuration → Webhooks
URL: http://jenkins-url/sonarqube-webhook/
Secret: [optionnel]
```

#### Analyse Multi-Module
```groovy
stage('SonarQube Analysis') {
    steps {
        withSonarQubeEnv('SonarQube') {
            sh '''
                sonar-scanner \
                -Dsonar.projectKey=fastapi-multi-module \
                -Dsonar.modules=api,core,utils \
                -Dapi.sonar.projectName="API Module" \
                -Dapi.sonar.sources=api \
                -Dcore.sonar.projectName="Core Module" \
                -Dcore.sonar.sources=core \
                -Dutils.sonar.projectName="Utils Module" \
                -Dutils.sonar.sources=utils
            '''
        }
    }
}
```

## 3. Intégration avec GitHub Actions

### 3.1 Configuration du Workflow

#### Fichier `.github/workflows/ci.yml`
```yaml
name: CI Pipeline with SonarQube

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test-and-analyze:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
    
    steps:
    - uses: actions/checkout@v3
      with:
        fetch-depth: 0  # Shallow clones should be disabled for better analysis
    
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
        cache: 'pip'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-cov
    
    - name: Run tests with coverage
      run: |
        pytest --junitxml=test-results.xml
        pytest --cov=. --cov-report=xml:coverage.xml
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/testdb
    
    - name: SonarQube Scan
      uses: SonarSource/sonarqube-scan-action@master
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        SONAR_HOST_URL: ${{ vars.SONAR_HOST_URL }}
      with:
        args: >
          -Dsonar.projectKey=fastapi-postgres
          -Dsonar.python.coverage.reportPaths=coverage.xml
          -Dsonar.python.xunit.reportPaths=test-results.xml
          -Dsonar.exclusions=venv/**,tests/**,**/__pycache__/**,*.pyc
    
    - name: SonarQube Quality Gate check
      uses: SonarSource/sonarqube-quality-gate-action@master
      timeout-minutes: 5
      env:
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        SONAR_HOST_URL: ${{ vars.SONAR_HOST_URL }}
    
    - name: Comment PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const projectKey = 'fastapi-postgres';
          const sonarUrl = `${{ vars.SONAR_HOST_URL }}/dashboard?id=${projectKey}&pullRequest=${{ github.event.pull_request.number }}`;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `## 📊 SonarQube Analysis
            
            [View detailed report on SonarQube](${sonarUrl})
            
            This PR has been analyzed by SonarQube. Check the quality gate status above.`
          });

  deploy:
    needs: test-and-analyze
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - name: Deploy to production
      run: |
        echo "🚀 Deploying to production..."
        # Commandes de déploiement
```

#### Configuration des Secrets et Variables
```bash
# Dans GitHub Repository Settings → Secrets and variables → Actions

# Secrets
SONAR_TOKEN: "your-sonarqube-token"

# Variables
SONAR_HOST_URL: "https://your-sonarqube-instance.com"
```

### 3.2 Workflow pour Monorepo

#### Structure Monorepo
```
monorepo/
├── .github/workflows/ci.yml
├── api/
│   ├── requirements.txt
│   ├── main.py
│   └── sonar-project.properties
├── core/
│   ├── requirements.txt
│   ├── models.py
│   └── sonar-project.properties
└── utils/
    ├── requirements.txt
    ├── helpers.py
    └── sonar-project.properties
```

#### Workflow Matrix pour Monorepo
```yaml
name: Monorepo CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  detect-changes:
    runs-on: ubuntu-latest
    outputs:
      api: ${{ steps.changes.outputs.api }}
      core: ${{ steps.changes.outputs.core }}
      utils: ${{ steps.changes.outputs.utils }}
    steps:
    - uses: actions/checkout@v3
    - uses: dorny/paths-filter@v2
      id: changes
      with:
        filters: |
          api:
            - 'api/**'
          core:
            - 'core/**'
          utils:
            - 'utils/**'

  test-and-analyze:
    needs: detect-changes
    runs-on: ubuntu-latest
    strategy:
      matrix:
        component: [api, core, utils]
        include:
          - component: api
            path: api
            test-cmd: pytest --cov=. --cov-report=xml:coverage.xml --junitxml=test-results.xml
          - component: core
            path: core
            test-cmd: pytest --cov=. --cov-report=xml:coverage.xml --junitxml=test-results.xml
          - component: utils
            path: utils
            test-cmd: pytest --cov=. --cov-report=xml:coverage.xml --junitxml=test-results.xml
    
    steps:
    - uses: actions/checkout@v3
      with:
        fetch-depth: 0
    
    - name: Check if component changed
      id: check-changes
      run: |
        if [ "${{ matrix.component }}" = "api" ] && [ "${{ needs.detect-changes.outputs.api }}" = "false" ]; then
          echo "skip=true" >> $GITHUB_OUTPUT
        elif [ "${{ matrix.component }}" = "core" ] && [ "${{ needs.detect-changes.outputs.core }}" = "false" ]; then
          echo "skip=true" >> $GITHUB_OUTPUT
        elif [ "${{ matrix.component }}" = "utils" ] && [ "${{ needs.detect-changes.outputs.utils }}" = "false" ]; then
          echo "skip=true" >> $GITHUB_OUTPUT
        else
          echo "skip=false" >> $GITHUB_OUTPUT
        fi
    
    - name: Setup Python
      if: steps.check-changes.outputs.skip != 'true'
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      if: steps.check-changes.outputs.skip != 'true'
      run: |
        cd ${{ matrix.path }}
        pip install -r requirements.txt
        pip install pytest pytest-cov
    
    - name: Run tests
      if: steps.check-changes.outputs.skip != 'true'
      run: |
        cd ${{ matrix.path }}
        ${{ matrix.test-cmd }}
    
    - name: SonarQube Analysis
      if: steps.check-changes.outputs.skip != 'true'
      uses: SonarSource/sonarqube-scan-action@master
      with:
        projectBaseDir: ${{ matrix.path }}
        args: >
          -Dsonar.projectKey=monorepo_${{ matrix.component }}
          -Dsonar.projectName="Monorepo ${{ matrix.component }}"
          -Dsonar.python.coverage.reportPaths=coverage.xml
          -Dsonar.python.xunit.reportPaths=test-results.xml
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        SONAR_HOST_URL: ${{ vars.SONAR_HOST_URL }}
```

## 4. Conventions et Politiques Qualité

### 4.1 Définition de Standards Qualité

#### Matrice de Qualité par Type de Projet
```yaml
# .sonarqube/quality-standards.yml
standards:
  fastapi-service:
    coverage:
      new_code: 85%
      overall: 80%
    complexity:
      max_function: 15
      max_file: 300
    duplication:
      max_percentage: 3%
    
  data-processing:
    coverage:
      new_code: 90%
      overall: 85%
    complexity:
      max_function: 20
      max_file: 500
    security:
      vulnerabilities: 0
      security_hotspots: 0
    
  cli-tool:
    coverage:
      new_code: 75%
      overall: 70%
    complexity:
      max_function: 12
      max_file: 250
    performance:
      max_method_lines: 30
```

#### Quality Gate Personnalisé par Équipe
```python
# Configuration Quality Gate "Strict Team"
strict_quality_gate = {
    "name": "Strict Team Standards",
    "conditions": [
        {
            "metric": "new_coverage",
            "operator": "LESS_THAN",
            "value": "90"
        },
        {
            "metric": "new_duplicated_lines_density",
            "operator": "GREATER_THAN", 
            "value": "2"
        },
        {
            "metric": "new_bugs",
            "operator": "GREATER_THAN",
            "value": "0"
        },
        {
            "metric": "new_vulnerabilities", 
            "operator": "GREATER_THAN",
            "value": "0"
        },
        {
            "metric": "new_code_smells",
            "operator": "GREATER_THAN",
            "value": "3"
        },
        {
            "metric": "new_maintainability_rating",
            "operator": "GREATER_THAN",
            "value": "1"  # Rating A
        }
    ]
}
```

### 4.2 Exceptions et Flexibilité

#### Configuration de Suppressions
```properties
# sonar-project.properties
sonar.exclusions=venv/**,tests/**,**/__pycache__/**,*.pyc,migrations/**,generated/**
sonar.coverage.exclusions=tests/**,migrations/**,setup.py
sonar.cpd.exclusions=tests/**,migrations/**

# Ignorer certaines règles pour des fichiers spécifiques
sonar.issue.ignore.multicriteria=e1,e2

# Ignorer la règle de complexité pour les fichiers de configuration
sonar.issue.ignore.multicriteria.e1.ruleKey=python:S3776
sonar.issue.ignore.multicriteria.e1.resourceKey=**/config.py

# Ignorer les règles de documentation pour les tests
sonar.issue.ignore.multicriteria.e2.ruleKey=python:S1192
sonar.issue.ignore.multicriteria.e2.resourceKey=**/test_*.py
```

#### Quality Gate Conditionnel
```groovy
// Dans Jenkins Pipeline
stage('Quality Gate') {
    steps {
        script {
            def qg = waitForQualityGate()
            
            if (qg.status != 'OK') {
                // Vérifier si c'est une branche de feature
                if (env.BRANCH_NAME.startsWith('feature/')) {
                    // Warning seulement pour les features
                    currentBuild.result = 'UNSTABLE'
                    echo "⚠️ Quality Gate failed but allowing feature branch"
                } else if (env.BRANCH_NAME == 'main' || env.BRANCH_NAME == 'develop') {
                    // Blocage strict pour main/develop
                    error "❌ Quality Gate failed for ${env.BRANCH_NAME}"
                } else {
                    // Politique flexible pour autres branches
                    echo "ℹ️ Quality Gate failed for ${env.BRANCH_NAME}, review needed"
                }
            }
        }
    }
}
```

### 4.3 Reporting et Métriques

#### Dashboard Custom
```python
# Configuration dashboard personnalisé
custom_dashboard = {
    "widgets": [
        {
            "type": "quality_gate_status",
            "projects": ["fastapi-postgres", "fastapi-auth-service", "data-processor"]
        },
        {
            "type": "coverage_trend", 
            "period": "30_days",
            "projects": ["all"]
        },
        {
            "type": "new_issues_breakdown",
            "severity": ["BLOCKER", "CRITICAL", "MAJOR"]
        },
        {
            "type": "technical_debt",
            "visualization": "effort_estimate"
        }
    ]
}
```

#### Rapports Automatiques
```yaml
# .github/workflows/quality-report.yml
name: Weekly Quality Report

on:
  schedule:
    - cron: '0 9 * * 1'  # Tous les lundis à 9h

jobs:
  quality-report:
    runs-on: ubuntu-latest
    steps:
    - name: Generate SonarQube Report
      run: |
        # Script pour générer rapport qualité hebdomadaire
        curl -u "${{ secrets.SONAR_TOKEN }}:" \
          "${{ vars.SONAR_HOST_URL }}/api/measures/search_history" \
          -G -d "component=fastapi-postgres" \
          -d "metrics=coverage,bugs,vulnerabilities,code_smells" \
          -d "from=$(date -d '7 days ago' '+%Y-%m-%d')" \
          > quality-metrics.json
    
    - name: Send Slack Report
      uses: 8398a7/action-slack@v3
      with:
        status: custom
        custom_payload: |
          {
            "text": "📊 Weekly Quality Report",
            "attachments": [{
              "color": "good",
              "fields": [
                {
                  "title": "Coverage",
                  "value": "85.2% (+2.1%)",
                  "short": true
                },
                {
                  "title": "New Bugs",
                  "value": "3 (-2 from last week)",
                  "short": true
                }
              ]
            }]
          }
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

## 5. Atelier Pratique : Pipeline Complet avec SonarQube

### 5.1 Exercice 1 : Pipeline Jenkins avec Quality Gate

#### Application de Démonstration
```python
# main.py
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime
import os

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///:memory:")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Database Models
class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


# Pydantic Models
class ItemCreate(BaseModel):
    name: str
    description: str = None


class ItemResponse(BaseModel):
    id: int
    name: str
    description: str = None
    created_at: datetime

    class Config:
        from_attributes = True


# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI with PostgreSQL", version="1.0.0")


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
async def root():
    return {"message": "Hello World - FastAPI with PostgreSQL"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "connected"}


@app.get("/items/", response_model=list[ItemResponse])
async def get_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    items = db.query(Item).offset(skip).limit(limit).all()
    return items


@app.get("/items/{item_id}", response_model=ItemResponse)
async def get_item(item_id: int, db: Session = Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@app.post("/items/", response_model=ItemResponse)
async def create_item(item: ItemCreate, db: Session = Depends(get_db)):
    db_item = Item(name=item.name, description=item.description)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item


@app.put("/items/{item_id}", response_model=ItemResponse)
async def update_item(item_id: int, item: ItemCreate, db: Session = Depends(get_db)):
    db_item = db.query(Item).filter(Item.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")

    db_item.name = item.name
    db_item.description = item.description
    db.commit()
    db.refresh(db_item)
    return db_item


@app.delete("/items/{item_id}")
async def delete_item(item_id: int, db: Session = Depends(get_db)):
    db_item = db.query(Item).filter(Item.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")

    db.delete(db_item)
    db.commit()
    return {"message": "Item deleted successfully"}
```

```python
# tests/test_api.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from datetime import datetime
from main import app, Item, get_db

# Create a fixture for the test client
@pytest.fixture
def client():
    return TestClient(app)

# Create a fixture for mocking the database session
@pytest.fixture
def mock_db():
    mock = MagicMock()
    app.dependency_overrides[get_db] = lambda: mock
    yield mock
    app.dependency_overrides.clear()

def test_read_root(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World - FastAPI with PostgreSQL"}

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "database": "connected"}

def test_get_items(client, mock_db):
    # Setup mock
    mock_items = [
        Item(
            id=1,
            name="Test Item 1",
            description="Description 1",
            created_at=datetime.utcnow()
        ),
        Item(
            id=2,
            name="Test Item 2",
            description="Description 2",
            created_at=datetime.utcnow()
        )
    ]
    mock_db.query.return_value.offset.return_value.limit.return_value.all.return_value = mock_items
    
    # Test
    response = client.get("/items/")
    
    # Assertions
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 2
    assert items[0]["name"] == "Test Item 1"
    assert items[1]["name"] == "Test Item 2"
```

#### Configuration sonar-project.properties
```properties
sonar.projectKey=fastapi-postgres
sonar.projectName=Fastapi Postgresql Application
sonar.projectVersion=1.0

sonar.sources=.
sonar.python.coverage.reportPaths=coverage.xml
sonar.python.xunit.reportPaths=test-results.xml

sonar.sourceEncoding=UTF-8

sonar.exclusions=venv/**,tests/**,**/__pycache__/**,*.pyc
```

#### Jenkinsfile Complet
```groovy
pipeline {
    agent any

    environment {
        PROJECT = "fadel"
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
                withSonarQubeEnv('MySonarqube') {
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

                    export PATH=$PATH:/var/lib/jenkins/sonar-scanner-4.7.0.2747-linux/bin
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

        stage('Quality Gate') {
            steps {
                timeout(time: 1, unit: 'HOURS') {
                    waitForQualityGate abortPipeline: true
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
                    docker.withRegistry("$REGISTRY_HOST", 'registry-credentials-fadel') {
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
```