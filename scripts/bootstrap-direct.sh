#!/usr/bin/env bash
set -euo pipefail

# ArgoCD Helm bootstrap
kubectl apply -f argocd/bootstrap/helm-job-sa.yaml --validate=false
kubectl apply -f argocd/bootstrap/argocd-helm-values.yaml --validate=false

kubectl apply -f argocd/bootstrap/argocd-helm-job.yaml --validate=false
kubectl wait --for=condition=complete job/helm-install-argocd --timeout=600s

# Post-install config
kubectl apply -f argocd/bootstrap/argocd-cm.yaml --validate=false
kubectl apply -f argocd/bootstrap/argocd-anon-rbac.yaml --validate=false

# Root applications
kubectl apply -f argocd/config/root-application.yaml
kubectl apply -f argocd/config/infra-application.yaml
