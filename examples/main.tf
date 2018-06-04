module "k8s" {
  source = "undeadops/k8s"

  # VPC DNS Zone
  dns_zone = "whiskey.example.com"

  vpc_id = "${module.vpc.vpc_id}"

  tag_env        = "prod"
  tag_costcenter = "whiskey"
  name           = "whiskey"
  k8s-ca-bucket  = "whiskey-ca"

  key_name = "mykey"

  vpc_id              = "${module.vpc.vpc_id}"
  zone_id             = "${module.route53.zone_id}"
  subnets             = ["${module.vpc.public_subnets}"]
  subnets_cidr_blocks = ["${module.vpc.public_subnets_cidr_blocks}"]
}
