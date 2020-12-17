kubectl delete configmap kong-plugin--auth -n dev
kubectl delete configmap kong-plugin--log -n dev
kubectl delete configmap kong-plugin--ip-filter -n dev
kubectl delete configmap kong-plugin-log -n dev

kubectl create configmap kong-plugin--auth --from-file=./-auth -n dev
kubectl create configmap kong-plugin--log --from-file=./-log -n dev
kubectl create configmap kong-plugin--ip-filter --from-file=./-ip-filter -n dev
kubectl create configmap kong-plugin-log --from-file=./kong-system-log -n dev