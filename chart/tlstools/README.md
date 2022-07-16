# nextcloud

[tlstools](https://github.com/jsandas/tlstools) is an api application for performing check on tls servers

## TL;DR;

```console
helm upgrade --install <release_name> oci://ghcr.io/jsandas/tlstools
```

## Introduction

This chart bootstraps a [tlstools](https://github.com/jsandas/tlstools) deployment on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

## Prerequisites

- Kubernetes 1.9+ with Beta APIs enabled
- Helm >=3.7.0

## Installing the Chart

To install the chart with the release name `my-release`:

```console
helm upgrade --install my-release oci://ghcr.io/jsandas/tlstools
```

The command deploys nextcloud on the Kubernetes cluster in the default configuration. The [configuration](#configuration) section lists the parameters that can be configured during installation.

> **Tip**: List all releases using `helm list`

## Uninstalling the Chart

To uninstall/delete the `my-release` deployment:

```console
helm delete my-release
```

The command removes all the Kubernetes components associated with the chart and deletes the release.

## Configuration

The following table lists the configurable parameters of the nextcloud chart and their default values.

| Parameter                                                    | Description                                             | Default                                     |
| ------------------------------------------------------------ | ------------------------------------------------------- | ------------------------------------------- |
| `replicaCount`                                               | Total Replicas                                         | `1` |
| `image.repository`                                           | tlstools Image name                                    | `ghcr.io/jsandas/tlstools/tlstools`                                 |
| `image.pullPolicy`                                           | Image pull policy                                       | `IfNotPresent`                              |
| `image.tag`                                                  | Overrides the image tag whose default is the chart appVersion                                    | `nil`                                 |
| `image.pullSecrets`                                          | Specify image pull secrets                              | `[]`                                       |
| `nameOverride`                                               | Override default chart name                              | `nil` | 
| `fullnameOverride`                                           | Override default chart fullname                          | `nil` |        
| `serviceAccount.create`                                 | Specifies whether a service account should be created | `true`                     |
| `serviceAccount.annotations`                                               | Annotations to add to the service account         | `{}`                                     |
| `serviceAccount.name`                                   | The name of the service account to use. If not set and create is true, a name is generated using the fullname template | `nil` |
|`podAnnotations`                                             | Annotations to be added at 'pod' level                  | `{}`                                 |
| `service.type`                                              |  Service Type                                           |  `ClusterIP` |
| `service.port`                                              |  Service Port                                           |  `80` |
| `ingress.enabled`                                            | Enable use of ingress controllers                       | `false`                                     |
| `ingress.className`                                          | Name of the ingress class to use                        | `nil`                                       |
| `ingress.annotations`                                        | An array of service annotations                         | `{}`                                       |
| `ingress.hosts`                                               | An array of ingress hosts with paths             |                              |
| `ingress.tls`                                                | Ingress TLS configuration                               | `[]`                                        |
|`resources`                                                  | CPU/Memory resource requests/limits                     | `{}`                                        |
| `autoscaling.enabled`                                                | Boolean to create a HorizontalPodAutoscaler             | `false`                                     |
| `autoscaling.minReplicas`                                                | Min. pods for the Nextcloud HorizontalPodAutoscaler     | `1`                                         |
| `autoscaling.maxReplicas`                                                | Max. pods for the Nextcloud HorizontalPodAutoscaler     | `100`                                        |
| `autoscaling.targetCPUUtilizationPercentage`                                           | CPU threshold percent for the HorizontalPodAutoscale    | `80`                                        |


Specify each parameter using the `--set key=value[,key=value]` argument to `helm install`. For example,

```console
helm install --name my-release \
  --set image.tag=latest \
  oci://ghcr.io/jsandas/tlstools
```

The above command sets the image  tag to `latest`. 

Alternatively, a YAML file that specifies the values for the above parameters can be provided while installing the chart. For example,

```console
helm install --name my-release -f values.yaml oci://ghcr.io/jsandas/tlstools
```

> **Tip**: You can use the default [values.yaml](values.yaml) for reference
