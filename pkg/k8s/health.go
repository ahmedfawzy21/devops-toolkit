package k8s

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
)

type HealthChecker struct {
	clientset *kubernetes.Clientset
}

type PodHealth struct {
	Namespace      string
	Name           string
	Status         string
	Ready          string
	Restarts       int32
	Age            time.Duration
	Node           string
}

type DeploymentHealth struct {
	Namespace string
	Name      string
	Ready     string
	UpToDate  int32
	Available int32
	Age       time.Duration
}

type NodeHealth struct {
	Name              string
	Status            string
	Roles             string
	Age               time.Duration
	KubeletVersion    string
	CPUCapacity       string
	MemoryCapacity    string
	PodCapacity       string
}

type EventInfo struct {
	Namespace string
	Kind      string
	Name      string
	Reason    string
	Message   string
	Count     int32
	LastSeen  time.Time
}

type HealthResults struct {
	Pods          []PodHealth
	Deployments   []DeploymentHealth
	Nodes         []NodeHealth
	WarningEvents []EventInfo
}

func NewHealthChecker() (*HealthChecker, error) {
	// Try to load kubeconfig from default location
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &HealthChecker{
		clientset: clientset,
	}, nil
}

func (h *HealthChecker) CheckPods(ctx context.Context, namespace string) ([]PodHealth, error) {
	pods, err := h.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	podHealths := make([]PodHealth, 0, len(pods.Items))
	
	for _, pod := range pods.Items {
		readyCount := 0
		totalContainers := len(pod.Status.ContainerStatuses)
		restarts := int32(0)

		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Ready {
				readyCount++
			}
			restarts += cs.RestartCount
		}

		age := time.Since(pod.CreationTimestamp.Time)

		podHealths = append(podHealths, PodHealth{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			Status:    string(pod.Status.Phase),
			Ready:     fmt.Sprintf("%d/%d", readyCount, totalContainers),
			Restarts:  restarts,
			Age:       age,
			Node:      pod.Spec.NodeName,
		})
	}

	return podHealths, nil
}

func (h *HealthChecker) CheckDeployments(ctx context.Context, namespace string) ([]DeploymentHealth, error) {
	deployments, err := h.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	depHealths := make([]DeploymentHealth, 0, len(deployments.Items))
	
	for _, dep := range deployments.Items {
		desired := int32(1)
		if dep.Spec.Replicas != nil {
			desired = *dep.Spec.Replicas
		}

		age := time.Since(dep.CreationTimestamp.Time)

		depHealths = append(depHealths, DeploymentHealth{
			Namespace: dep.Namespace,
			Name:      dep.Name,
			Ready:     fmt.Sprintf("%d/%d", dep.Status.ReadyReplicas, desired),
			UpToDate:  dep.Status.UpdatedReplicas,
			Available: dep.Status.AvailableReplicas,
			Age:       age,
		})
	}

	return depHealths, nil
}

func (h *HealthChecker) CheckNodes(ctx context.Context) ([]NodeHealth, error) {
	nodes, err := h.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	nodeHealths := make([]NodeHealth, 0, len(nodes.Items))
	
	for _, node := range nodes.Items {
		status := "Unknown"
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady {
				if condition.Status == corev1.ConditionTrue {
					status = "Ready"
				} else {
					status = "NotReady"
				}
				break
			}
		}

		roles := getRoles(node.Labels)
		age := time.Since(node.CreationTimestamp.Time)

		nodeHealths = append(nodeHealths, NodeHealth{
			Name:              node.Name,
			Status:            status,
			Roles:             roles,
			Age:               age,
			KubeletVersion:    node.Status.NodeInfo.KubeletVersion,
			CPUCapacity:       node.Status.Capacity.Cpu().String(),
			MemoryCapacity:    node.Status.Capacity.Memory().String(),
			PodCapacity:       node.Status.Capacity.Pods().String(),
		})
	}

	return nodeHealths, nil
}

func (h *HealthChecker) GetRecentWarningEvents(ctx context.Context, namespace string) ([]EventInfo, error) {
	events, err := h.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}

	// Filter warning events from last hour
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	eventInfos := make([]EventInfo, 0)

	for _, event := range events.Items {
		if event.Type == corev1.EventTypeWarning && event.LastTimestamp.After(oneHourAgo) {
			eventInfos = append(eventInfos, EventInfo{
				Namespace: event.Namespace,
				Kind:      event.InvolvedObject.Kind,
				Name:      event.InvolvedObject.Name,
				Reason:    event.Reason,
				Message:   event.Message,
				Count:     event.Count,
				LastSeen:  event.LastTimestamp.Time,
			})
		}
	}

	return eventInfos, nil
}

func getRoles(labels map[string]string) string {
	roles := ""
	for key := range labels {
		if key == "node-role.kubernetes.io/master" || key == "node-role.kubernetes.io/control-plane" {
			if roles != "" {
				roles += ","
			}
			roles += "control-plane"
		} else if key == "node-role.kubernetes.io/worker" {
			if roles != "" {
				roles += ","
			}
			roles += "worker"
		}
	}
	
	if roles == "" {
		roles = "<none>"
	}
	
	return roles
}
