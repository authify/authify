# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying Authify to a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (1.25+)
- kubectl configured to access your cluster
- NGINX Ingress Controller
- cert-manager (for automatic TLS certificates)
- Persistent Volume provisioner

## Quick Start

1. **Update configuration**:
   - Edit `configmap.yaml` - set your domain in `PHX_HOST`
   - Edit `secret.yaml` - generate secrets with `mix phx.gen.secret`
   - Edit `ingress.yaml` - set your domain
   - Edit `deployment.yaml` - update image references

2. **Deploy**:
   ```bash
   # Create namespace
   kubectl apply -f namespace.yaml

   # Create configuration
   kubectl apply -f configmap.yaml
   kubectl apply -f secret.yaml

   # Deploy MySQL
   kubectl apply -f mysql-statefulset.yaml

   # Wait for MySQL to be ready
   kubectl wait --for=condition=ready pod -l app=authify-mysql -n authify --timeout=300s

   # Set up RBAC for clustering (required for libcluster)
   kubectl apply -f rbac.yaml

   # Deploy Authify
   kubectl apply -f deployment.yaml
   kubectl apply -f service.yaml
   kubectl apply -f ingress.yaml

   # Optional: Enable auto-scaling
   kubectl apply -f hpa.yaml
   ```

3. **Verify deployment**:
   ```bash
   # Check pods
   kubectl get pods -n authify

   # Check services
   kubectl get svc -n authify

   # Check ingress
   kubectl get ingress -n authify

   # View logs
   kubectl logs -n authify -l app=authify -f
   ```

## Components

### Namespace (`namespace.yaml`)
Creates the `authify` namespace for all resources.

### ConfigMap (`configmap.yaml`)
Non-sensitive configuration:
- `PHX_HOST` - Your domain name
- `PORT` - Application port (4000)
- `POOL_SIZE` - Database connection pool size
- `ENABLE_METRICS` - Enable Prometheus metrics
- `RELEASE_NAMESPACE` - Kubernetes namespace for clustering
- `CLUSTER_SERVICE_NAME` - Headless service name for node discovery (default: `authify-internal`)

### Secret (`secret.yaml`)
Sensitive configuration:
- `SECRET_KEY_BASE` - Phoenix secret (generate with `mix phx.gen.secret`)
- `RELEASE_COOKIE` - Erlang distribution cookie
- `DATABASE_URL` - MySQL connection string

**Important**: Replace all placeholder values before deploying!

### MySQL StatefulSet (`mysql-statefulset.yaml`)
- Single-replica MySQL 8.0
- 10Gi persistent volume
- Health checks configured
- **Production Note**: Consider using a managed database service (AWS RDS, Google Cloud SQL, etc.)

### RBAC (`rbac.yaml`)
- ServiceAccount for Authify pods
- Role with permissions to read pods and endpoints
- RoleBinding to grant permissions
- **Required for libcluster** to discover pods via Kubernetes API

### Deployment (`deployment.yaml`)
- 2 replicas for high availability
- Init container runs database migrations
- Health checks (liveness + readiness)
- Resource requests and limits
- Erlang clustering configured with EPMD (port 4369)
- Uses Kubernetes downward API for dynamic node naming
- **Update image references** to your container registry

### Service (`service.yaml`)
Two services are created:
- **`authify-internal` (headless)**: ClusterIP: None, ports 4000 (HTTP) and 4369 (EPMD)
  - Required for Erlang clustering and DNS-based node discovery
  - Not used for external traffic
- **`authify`**: ClusterIP service, port 80 → 4000
  - Used by Ingress for external HTTP traffic

### Ingress (`ingress.yaml`)
- NGINX ingress controller
- Automatic TLS with cert-manager
- Rate limiting configured
- **Update domain** to your actual domain

### Horizontal Pod Autoscaler (`hpa.yaml`)
- Scales 2-10 replicas
- Based on CPU (70%) and memory (80%)
- Gradual scale-down, fast scale-up

## Production Considerations

### Security
1. **Update all secrets** in `secret.yaml`
2. **Use external secrets** (e.g., HashiCorp Vault, AWS Secrets Manager)
3. **Enable Pod Security Standards**
4. **Configure Network Policies**

### Database
1. **Use managed database** instead of StatefulSet
2. **Configure backups**
3. **Set up monitoring**
4. **Use read replicas** for high traffic

### Observability

#### Metrics

Authify exposes Prometheus metrics on port **9568** at `/metrics` on each pod.

**Important**: Metrics are **node-local** and must be scraped from each pod individually, not through a Service.

**Why Per-Pod Scraping?**

Each Elixir node tracks its own HTTP requests, database queries, memory/CPU usage, and VM statistics. If you scrape through a Service, the load balancer will randomly hit different pods and you'll miss metrics.

**Option 1: Prometheus Operator (Recommended)**

```bash
# Apply the ServiceMonitor (tells Prometheus to scrape all pods)
kubectl apply -f servicemonitor.yaml
```

**Note**: Update the `release` label in `servicemonitor.yaml` to match your Prometheus instance's `serviceMonitorSelector`.

**Option 2: Standard Prometheus**

The deployment includes these annotations for automatic pod discovery:
- `prometheus.io/scrape: "true"`
- `prometheus.io/port: "9568"`
- `prometheus.io/path: "/metrics"`

Configure Prometheus to scrape pods with these annotations (see `servicemonitor.yaml` comments for config example).

**Useful Queries**:
```promql
# Total requests per second across all pods
sum(rate(phoenix_endpoint_stop_duration_count[5m]))

# Requests per organization
sum by (organization) (rate(phoenix_endpoint_stop_duration_count[5m]))

# 95th percentile latency
histogram_quantile(0.95, rate(phoenix_endpoint_stop_duration_bucket[5m]))
```

#### Logs

Configure log aggregation (ELK, Loki, etc.)

#### Tracing

Consider adding OpenTelemetry

### High Availability
1. **Multiple replicas**: Already configured (2 minimum)
2. **Erlang clustering**: Pods automatically discover and connect to each other
   - Uses libcluster with Kubernetes API strategy
   - Enables distributed rate limiting and session sharing
   - Requires RBAC permissions (configured in `rbac.yaml`)
3. **Pod Disruption Budget**:
   ```yaml
   apiVersion: policy/v1
   kind: PodDisruptionBudget
   metadata:
     name: authify
     namespace: authify
   spec:
     minAvailable: 1
     selector:
       matchLabels:
         app: authify
   ```

4. **Multi-zone deployment**: Use node affinity/anti-affinity

### Scaling
- HPA handles automatic scaling
- For manual scaling: `kubectl scale deployment authify -n authify --replicas=5`
- Monitor metrics to tune HPA thresholds

## Updating

### Rolling Update
```bash
# Update image in deployment.yaml, then:
kubectl apply -f deployment.yaml

# Watch rollout
kubectl rollout status deployment/authify -n authify
```

### Rollback
```bash
kubectl rollout undo deployment/authify -n authify
```

## Troubleshooting

### Pods not starting
```bash
# Check pod status
kubectl describe pod <pod-name> -n authify

# Check logs
kubectl logs <pod-name> -n authify

# Check init container logs
kubectl logs <pod-name> -n authify -c migrate
```

### Database connection issues
```bash
# Test MySQL connectivity
kubectl run -it --rm debug --image=mysql:8.4 --restart=Never -n authify -- \
  mysql -h authify-mysql -u authify -p

# Check MySQL logs
kubectl logs authify-mysql-0 -n authify
```

### Ingress not working
```bash
# Check ingress
kubectl describe ingress authify -n authify

# Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/component=controller
```

### Clustering issues
```bash
# Check if pods are connected to the cluster
kubectl exec -n authify deployment/authify -- /app/bin/authify rpc "Node.list()"

# Check libcluster logs for connection issues
kubectl logs -n authify -l app=authify --tail=100 | grep -i "libcluster\|cluster"

# Verify RBAC permissions are configured
kubectl get serviceaccount authify -n authify
kubectl get role authify-pod-reader -n authify
kubectl get rolebinding authify-pod-reader -n authify

# Check if headless service exists
kubectl get service authify-internal -n authify -o yaml

# Verify EPMD port is exposed
kubectl get pods -n authify -o jsonpath='{.items[0].spec.containers[0].ports}'

# Check DNS resolution from within a pod
kubectl exec -n authify deployment/authify -- nslookup authify.authify.svc.cluster.local

# Check RELEASE_COOKIE matches across all pods
kubectl exec -n authify deployment/authify -- env | grep RELEASE_COOKIE
```

**Common issues:**
- Missing RBAC permissions: Apply `rbac.yaml`
- Mismatched `RELEASE_COOKIE`: Update in `secret.yaml`
- Wrong `CLUSTER_SERVICE_NAME`: Update in `configmap.yaml`
- Headless service missing: Apply `service.yaml`

## Cleanup

```bash
# Delete all resources
kubectl delete namespace authify
```

## Additional Resources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/)
- [cert-manager](https://cert-manager.io/docs/)
- [Horizontal Pod Autoscaler](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/)
