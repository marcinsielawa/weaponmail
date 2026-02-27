# Kubernetes Deployment Guide

This directory contains basic Kubernetes manifests for deploying Weapon Mail to a local cluster (minikube or kind).

## Prerequisites

- [minikube](https://minikube.sigs.k8s.io/docs/start/) or [kind](https://kind.sigs.k8s.io/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- Docker

## Build Images

Build the Docker images locally and load them into the cluster:

```bash
# Build images
docker build -t weaponmail-backend:latest ./backend
docker build -t weaponmail-frontend:latest ./frontend

# Load into minikube
minikube image load weaponmail-backend:latest
minikube image load weaponmail-frontend:latest

# Or load into kind
kind load docker-image weaponmail-backend:latest
kind load docker-image weaponmail-frontend:latest
```

## Deploy

Apply the manifests in dependency order:

```bash
# 1. ScyllaDB (StatefulSet)
kubectl apply -f k8s/scylladb-statefulset.yaml

# Wait for ScyllaDB to be ready
kubectl rollout status statefulset/scylladb

# 2. Backend
kubectl apply -f k8s/backend-deployment.yaml

# 3. Frontend
kubectl apply -f k8s/frontend-deployment.yaml
```

## Access the Application

```bash
# Get the frontend NodePort URL (minikube)
minikube service weaponmail-frontend --url

# Or port-forward manually
kubectl port-forward service/weaponmail-frontend 4200:4200
kubectl port-forward service/weaponmail-backend 8080:8080
```

## Tear Down

```bash
kubectl delete -f k8s/
```

## Notes

- These manifests use `imagePullPolicy: Never` so images must be pre-loaded into the cluster.
- For production, replace with a registry-based image pull policy and add resource limits.
- ScyllaDB uses a single replica with developer mode; add more replicas and remove `--developer-mode` for production.
