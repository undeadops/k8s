terraform {
  required_version = ">= 0.11.7" # Currently only testing with latest version of terraform
}

resource "aws_s3_bucket" "k8s-ca-bucket" {
  bucket = "${var.k8s-ca-bucket}"
  acl    = "private"

  tags {
    Name            = "${var.k8s-ca-bucket}"
    KubeEnvironment = "${var.name}"
    env             = "${var.tag_env}"
    cost_center     = "${var.tag_costcenter}"
  }
}
