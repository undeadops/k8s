variable "dns_zone" {
  description = "Name of the Route53 Zone"
  default     = "bar.foo.local"
}

variable "tag_env" {
  description = "Environment Tag to be added to EC2 Instances"
  default     = "dev"
}

variable "tag_costcenter" {
  description = "Cost Center Tag to be added to EC2 Instances"
  default     = "foobar"
}

variable "ssh_key_name" {
  description = "AWS SSH Key to attach the EC2 Instances"
  default     = "foobar"
}

variable "tag_master_role" {
  description = "Kube Master Role Tag"
  default     = "master-foo"
}

variable "tag_worker_role" {
  description = "Kube Worker Role Tag"
  default     = "worker-foo"
}

variable "vpc_id" {
  description = "AWS VPC ID"
  default     = ""
}

variable "subnets" {
  description = "AWS Subnets to Use"
  default     = []
}

variable "subnets_cidr_blocks" {
  description = "AWS Subnet CIDR Blocks Used"
  default     = []
}

variable "zone_id" {
  description = "Private DNS zone for VPC"
  default     = []
}

variable "name" {
  description = "Name of Kubernetes Cluster or something..."
  default     = ""
}

variable "master_ec2_instance_type" {
  description = "EC2 Instance type for Master API Servers"
  default     = "t2.medium"
}

variable "master_ebs_optimized" {
  description = "EC2 Instance EBS Optimization"
  default     = false
}

variable "master_volume_type" {
  description = "EC2 Master Instance Root Volume Type"
  default     = "gp2"
}

variable "master_volume_size" {
  description = "EC2 Master Instance Root Volume Size"
  default     = "200"
}

variable "key_name" {
  description = "AWS SSH Key Name to Use"
  default     = "foobar"
}

variable "kube_version" {
  description = "Kubernetes Version to Deploy"
  default     = "1.9.3"
}

variable "dns_service_ip" {
  description = "Kubernetes DNS Service IP"
  default     = "10.3.0.1"
}

variable "k8s-ca-bucket" {
  description = "Bucket to Store CA Pub and Private Keys"
  default     = "foo-bar"
}

variable "aws_region" {
  description = "AWS Region our VPC is in"
  default     = "us-east-1"
}
