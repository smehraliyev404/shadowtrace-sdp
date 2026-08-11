# ShadowTrace: SDP and Research Paper

### Set Up Python Virtual Environment

```bash
# Create a Python virtual environment
python3 -m venv venv

# Activate virtual environment (macOS/Linux)
source venv/bin/activate

# On Windows (Command Prompt):
# venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### MacOS setup


1. Docker Desktop

```bash

Install from docker.com and launch it.

In Settings → Resources, set CPUs: 4+ and Memory: 8 GB+. Minikube can only use what Docker has, and 11 services need room.

bash
docker ps          # should not error

```



2. Install the tools

```bash

bash
brew install kubectl minikube

```

3. Start the cluster

```bash

--driver=docker is what makes the Kubernetes node run inside Docker.

bash
minikube start --driver=docker --cpus=4 --memory=8192

```

4. Verify

```bash

bash
minikube status                  # all Running
kubectl get nodes                # STATUS: Ready
kubectl config current-context   # minikube

```

### Windows setup

Use PowerShell as Administrator for all commands.


```bash

1. Docker Desktop

Install from docker.com and enable the WSL 2 backend when prompted. If WSL isn't installed:

powershell



wsl --install     # then restart your PC

Launch Docker Desktop. In Settings → Resources, set CPUs: 4+ and Memory: 8 GB+.

powershell


docker ps          # should not error

```


2. Install the tools

```bash


powershell


choco install kubernetes-cli minikube -y

Then close and reopen PowerShell so the commands are found.

```


3. Start the cluster

```bash


--driver=docker is what makes the Kubernetes node run inside Docker.

powershell


minikube start --driver=docker --cpus=4 --memory=8192

```


4. Verify


```bash

powershell



minikube status                  # all Running
kubectl get nodes                # STATUS: Ready
kubectl config current-context   # minikube
Deploy

1. Clone the repo

bash
git clone --depth 1 --branch v0 https://github.com/GoogleCloudPlatform/microservices-demo.git
cd microservices-demo

2. Create the pods

Everything is in one manifest file:

bash
kubectl apply -f ./release/kubernetes-manifests.yaml

3. Wait for them to start

bash
kubectl get pods -w

Wait until all 12 pods show Running and READY 1/1 — takes 2–5 minutes on first run while images download. Ctrl+C to stop watching.



adservice-...               1/1   Running
cartservice-...             1/1   Running
checkoutservice-...         1/1   Running
currencyservice-...         1/1   Running
emailservice-...            1/1   Running
frontend-...                1/1   Running
loadgenerator-...           1/1   Running
paymentservice-...          1/1   Running
productcatalogservice-...   1/1   Running
recommendationservice-...   1/1   Running
redis-cart-...              1/1   Running
shippingservice-...         1/1   Running


```


4. Open the shop

```bash


bash
minikube service frontend-external

This opens your browser automatically.

kubectl get svc will show frontend-external with EXTERNAL-IP stuck on <pending>. That's normal — Minikube has no cloud load balancer, so use minikube service instead.

Useful commands
Command	What it does
kubectl get pods	List pods and status
kubectl logs <pod>	View a pod's logs
kubectl logs -f <pod>	Follow logs live
kubectl describe pod <pod>	Why a pod won't start
kubectl exec -it <pod> -- sh	Shell into a pod
minikube dashboard	Open the Kubernetes web UI

Turn off the built-in load generator (it sends constant fake traffic — disable it before taking any measurements):

bash
kubectl scale deployment loadgenerator --replicas=0
Clean up
bash
kubectl delete -f ./release/kubernetes-manifests.yaml   # remove the app
minikube stop                                           # pause the cluster
minikube delete                                         # wipe it completely


```

