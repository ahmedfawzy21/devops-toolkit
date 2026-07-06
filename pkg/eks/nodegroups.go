package eks

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

const (
	// rebalanceThresholdPercent is the On-Demand share above which a node group
	// is considered a candidate for shifting some capacity to Spot.
	rebalanceThresholdPercent = 70.0

	// rebalanceMoveFraction is the fraction of On-Demand nodes the rough
	// estimate assumes could move to Spot.
	rebalanceMoveFraction = 0.30

	// spotDiscount is the assumed Spot discount versus On-Demand.
	spotDiscount = 0.60
)

// NodeGroupAuditor reports the Spot vs On-Demand mix of a cluster's node
// groups. Managed node groups expose their capacity type directly via the EKS
// API; self-managed / Karpenter-style groups are inspected per-instance via
// EC2.
type NodeGroupAuditor struct {
	eksClient *eks.Client
	ec2Client *ec2.Client
	region    string
}

// NodeGroupRatio summarizes the capacity mix of a single node group.
type NodeGroupRatio struct {
	NodeGroupName                       string
	TotalNodes                          int
	OnDemandCount                       int
	SpotCount                           int
	OnDemandPercent                     float64
	EstimatedMonthlySavingsIfRebalanced float64
}

// NewNodeGroupAuditor builds a NodeGroupAuditor from the default AWS SDK config
// for the given region.
func NewNodeGroupAuditor(ctx context.Context, region string) (*NodeGroupAuditor, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	return &NodeGroupAuditor{
		eksClient: eks.NewFromConfig(cfg),
		ec2Client: ec2.NewFromConfig(cfg),
		region:    region,
	}, nil
}

// GetSpotRatioByNodeGroup returns the Spot/On-Demand ratio for every node group
// in the cluster. For managed node groups it reads CapacityType directly; only
// when CapacityType is unset (self-managed / Karpenter) does it fall back to
// per-instance EC2 inspection.
func (a *NodeGroupAuditor) GetSpotRatioByNodeGroup(ctx context.Context, clusterName string) ([]NodeGroupRatio, error) {
	names, err := a.listNodegroups(ctx, clusterName)
	if err != nil {
		return nil, err
	}

	ratios := make([]NodeGroupRatio, 0, len(names))
	for _, name := range names {
		out, err := a.eksClient.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
			ClusterName:   aws.String(clusterName),
			NodegroupName: aws.String(name),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe nodegroup %s: %w", name, err)
		}

		ratio, err := a.ratioForNodegroup(ctx, clusterName, out.Nodegroup)
		if err != nil {
			return nil, err
		}
		ratios = append(ratios, ratio)
	}

	return ratios, nil
}

// listNodegroups returns all node group names for a cluster, following
// pagination.
func (a *NodeGroupAuditor) listNodegroups(ctx context.Context, clusterName string) ([]string, error) {
	names := make([]string, 0)
	var nextToken *string

	for {
		out, err := a.eksClient.ListNodegroups(ctx, &eks.ListNodegroupsInput{
			ClusterName: aws.String(clusterName),
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list nodegroups for cluster %s: %w", clusterName, err)
		}

		names = append(names, out.Nodegroups...)

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return names, nil
}

// ratioForNodegroup computes the capacity mix for one node group, preferring
// the managed-nodegroup CapacityType and falling back to EC2 inspection.
func (a *NodeGroupAuditor) ratioForNodegroup(ctx context.Context, clusterName string, ng *ekstypes.Nodegroup) (NodeGroupRatio, error) {
	name := aws.ToString(ng.NodegroupName)
	instanceType := firstInstanceType(ng.InstanceTypes)

	var total, onDemand, spot int

	switch ng.CapacityType {
	case ekstypes.CapacityTypesSpot:
		total = desiredSize(ng)
		spot = total
	case ekstypes.CapacityTypesOnDemand:
		total = desiredSize(ng)
		onDemand = total
	default:
		// CapacityType not set (self-managed / Karpenter): inspect the actual
		// instances' lifecycle via EC2.
		od, sp, err := a.countInstanceLifecycle(ctx, clusterName, name)
		if err != nil {
			return NodeGroupRatio{}, err
		}
		onDemand, spot = od, sp
		total = od + sp
	}

	ratio := NodeGroupRatio{
		NodeGroupName:   name,
		TotalNodes:      total,
		OnDemandCount:   onDemand,
		SpotCount:       spot,
		OnDemandPercent: onDemandPercent(onDemand, total),
	}
	ratio.EstimatedMonthlySavingsIfRebalanced = estimateRebalanceSavings(onDemand, ratio.OnDemandPercent, nodeMonthlyCost(instanceType))

	return ratio, nil
}

// countInstanceLifecycle counts running On-Demand vs Spot instances belonging
// to a node group, identified by the EKS-applied tags. An empty
// InstanceLifecycle means On-Demand.
func (a *NodeGroupAuditor) countInstanceLifecycle(ctx context.Context, clusterName, nodegroupName string) (int, int, error) {
	var onDemand, spot int
	var nextToken *string

	for {
		out, err := a.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			Filters: []ec2types.Filter{
				{Name: aws.String("tag:eks:nodegroup-name"), Values: []string{nodegroupName}},
				{Name: aws.String("tag:eks:cluster-name"), Values: []string{clusterName}},
				{Name: aws.String("instance-state-name"), Values: []string{"running"}},
			},
			NextToken: nextToken,
		})
		if err != nil {
			return 0, 0, fmt.Errorf("failed to describe instances for nodegroup %s: %w", nodegroupName, err)
		}

		for _, reservation := range out.Reservations {
			for _, instance := range reservation.Instances {
				if instance.InstanceLifecycle == ec2types.InstanceLifecycleTypeSpot {
					spot++
				} else {
					onDemand++
				}
			}
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	return onDemand, spot, nil
}

// desiredSize returns the node group's desired size, or 0 when unset.
func desiredSize(ng *ekstypes.Nodegroup) int {
	if ng.ScalingConfig != nil && ng.ScalingConfig.DesiredSize != nil {
		return int(aws.ToInt32(ng.ScalingConfig.DesiredSize))
	}
	return 0
}

// firstInstanceType returns the first instance type of a node group, or "".
func firstInstanceType(instanceTypes []string) string {
	if len(instanceTypes) > 0 {
		return instanceTypes[0]
	}
	return ""
}

// onDemandPercent returns the On-Demand share as a percentage, guarding against
// division by zero.
func onDemandPercent(onDemand, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(onDemand) / float64(total) * 100
}

// estimateRebalanceSavings is a rough, clearly-labeled estimate: when a node
// group is more than rebalanceThresholdPercent On-Demand, it assumes
// rebalanceMoveFraction of the On-Demand nodes could move to Spot at
// spotDiscount off. Returns 0 below the threshold.
func estimateRebalanceSavings(onDemandCount int, onDemandPercent, monthlyCostPerNode float64) float64 {
	if onDemandPercent <= rebalanceThresholdPercent {
		return 0
	}
	nodesToMove := rebalanceMoveFraction * float64(onDemandCount)
	return nodesToMove * monthlyCostPerNode * spotDiscount
}
