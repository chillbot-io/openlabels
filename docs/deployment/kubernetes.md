# Kubernetes Deployment Guide

Deploy OpenLabels on Kubernetes for scalable, cloud-native file scanning.

## Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- Persistent storage provisioner (for index database)

## Quick Start

```bash
# Apply manifests
kubectl apply -f kubernetes/

# Check deployment
kubectl get pods -l app=openlabels
```

## Manifests

### Namespace

```yaml
# kubernetes/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: openlabels
  labels:
    app.kubernetes.io/name: openlabels
```

### ConfigMap

```yaml
# kubernetes/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: openlabels-config
  namespace: openlabels
data:
  OPENLABELS_LOG_LEVEL: "INFO"
  OPENLABELS_LOG_FORMAT: "json"
  OPENLABELS_DEFAULT_EXPOSURE: "INTERNAL"
```

### PersistentVolumeClaim

```yaml
# kubernetes/pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: openlabels-index
  namespace: openlabels
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
```

### Deployment (File Watcher)

```yaml
# kubernetes/deployment-watcher.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openlabels-watcher
  namespace: openlabels
  labels:
    app: openlabels
    component: watcher
spec:
  replicas: 1  # Single replica for file watching
  selector:
    matchLabels:
      app: openlabels
      component: watcher
  template:
    metadata:
      labels:
        app: openlabels
        component: watcher
    spec:
      serviceAccountName: openlabels
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: watcher
          image: openlabels:latest
          imagePullPolicy: IfNotPresent
          args:
            - watch
            - /data
            - --recursive
          envFrom:
            - configMapRef:
                name: openlabels-config
          resources:
            requests:
              memory: "512Mi"
              cpu: "250m"
            limits:
              memory: "2Gi"
              cpu: "1000m"
          volumeMounts:
            - name: data
              mountPath: /data
              readOnly: true
            - name: index
              mountPath: /home/openlabels/.openlabels
          livenessProbe:
            exec:
              command:
                - openlabels
                - health
                - --check
                - python
            initialDelaySeconds: 30
            periodSeconds: 60
          readinessProbe:
            exec:
              command:
                - openlabels
                - health
            initialDelaySeconds: 10
            periodSeconds: 30
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: data-pvc  # Your data PVC
        - name: index
          persistentVolumeClaim:
            claimName: openlabels-index
```

### CronJob (Scheduled Scan)

```yaml
# kubernetes/cronjob-scan.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: openlabels-scan
  namespace: openlabels
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        spec:
          serviceAccountName: openlabels
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
          restartPolicy: OnFailure
          containers:
            - name: scanner
              image: openlabels:latest
              args:
                - scan
                - /data
                - --recursive
                - --format
                - json
                - --output
                - /results/scan-$(date +%Y%m%d).json
              envFrom:
                - configMapRef:
                    name: openlabels-config
              resources:
                requests:
                  memory: "1Gi"
                  cpu: "500m"
                limits:
                  memory: "4Gi"
                  cpu: "2000m"
              volumeMounts:
                - name: data
                  mountPath: /data
                  readOnly: true
                - name: results
                  mountPath: /results
                - name: index
                  mountPath: /home/openlabels/.openlabels
          volumes:
            - name: data
              persistentVolumeClaim:
                claimName: data-pvc
            - name: results
              persistentVolumeClaim:
                claimName: scan-results-pvc
            - name: index
              persistentVolumeClaim:
                claimName: openlabels-index
```

### ServiceAccount and RBAC

```yaml
# kubernetes/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: openlabels
  namespace: openlabels
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: openlabels
  namespace: openlabels
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: openlabels
  namespace: openlabels
subjects:
  - kind: ServiceAccount
    name: openlabels
    namespace: openlabels
roleRef:
  kind: Role
  name: openlabels
  apiGroup: rbac.authorization.k8s.io
```

### NetworkPolicy

```yaml
# kubernetes/networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: openlabels
  namespace: openlabels
spec:
  podSelector:
    matchLabels:
      app: openlabels
  policyTypes:
    - Ingress
    - Egress
  ingress: []  # No ingress needed for CLI tool
  egress:
    - to: []  # Allow DNS
      ports:
        - protocol: UDP
          port: 53
```

## Helm Chart

For easier deployment, use the Helm chart:

```bash
# Add repo
helm repo add openlabels https://charts.openlabels.io

# Install
helm install openlabels openlabels/openlabels \
  --namespace openlabels \
  --create-namespace \
  --set dataVolume.existingClaim=my-data-pvc \
  --set config.logLevel=INFO
```

### Values

```yaml
# values.yaml
replicaCount: 1

image:
  repository: openlabels
  tag: latest
  pullPolicy: IfNotPresent

config:
  logLevel: INFO
  logFormat: json
  defaultExposure: INTERNAL

dataVolume:
  existingClaim: ""  # Use existing PVC
  # Or create new:
  size: 100Gi
  storageClassName: standard

indexVolume:
  size: 10Gi
  storageClassName: standard

resources:
  requests:
    memory: 512Mi
    cpu: 250m
  limits:
    memory: 2Gi
    cpu: 1000m

cronJob:
  enabled: true
  schedule: "0 2 * * *"

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
```

## Monitoring

### Prometheus Metrics

```yaml
# Add annotations for Prometheus scraping
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
    prometheus.io/path: "/metrics"
```

### Grafana Dashboard

Import the OpenLabels dashboard from `dashboards/grafana-openlabels.json`.

## Troubleshooting

### Pod won't start

```bash
# Check pod status
kubectl describe pod -l app=openlabels -n openlabels

# Check logs
kubectl logs -l app=openlabels -n openlabels

# Check events
kubectl get events -n openlabels --sort-by='.lastTimestamp'
```

### Permission denied

```bash
# Check security context
kubectl get pod -l app=openlabels -n openlabels -o yaml | grep -A10 securityContext

# Verify PVC permissions
kubectl exec -it <pod> -n openlabels -- ls -la /data
```

### Out of memory

Increase resource limits:

```bash
kubectl patch deployment openlabels-watcher -n openlabels \
  --type=json \
  -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/resources/limits/memory", "value": "4Gi"}]'
```
