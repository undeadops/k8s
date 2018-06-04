# User Data
data "template_file" "master-userdata" {
  template = "${file("${path.module}/templates/apiservers-userdata")}"
  count    = "${length(var.subnets)}"

  vars {
    host_name = "${format("%s-master%02d", var.tag_costcenter, count.index)}"
    dns_name  = "${var.dns_zone}"

    #dns-service-ip = "${var.dns_service_name}"
  }
}

provider "ignition" {
  version = "v1.0.0"
}

data "ignition_systemd_unit" "k8s-master" {
  name    = "etcd-member.service"
  enabled = true
  count   = "${length(var.subnets)}"

  content = <<EOF
[Unit]
Requires=coreos-metadata.service
After=coreos-metadata.service
After=network.target

[Install]
WantedBy=multi-user.target

[Service]
Restart=on-failure
RestartSec=6
EnvironmentFile=/run/metadata/coreos
Environment="ETCD_IMAGE_TAG=v3.2.17"
Environment="ETCD_USER=etcd"
Environment="ETCD_DATA_DIR=/var/lib/etcd"
ExecStart=
ExecStart=/usr/lib/coreos/etcd-wrapper $ETCD_OPTS \
  --name="${format("master%02d.%s", count.index + 1, var.dns_zone)}" \
  --advertise-client-urls http://$${COREOS_EC2_IPV4_LOCAL}:2379,http://$${COREOS_EC2_IPV4_LOCAL}:4001 \
  --initial-advertise-peer-urls="http://$${COREOS_EC2_IPV4_LOCAL}:2380" \
  --listen-client-urls="http://0.0.0.0:2379" \
  --listen-peer-urls="http://$${COREOS_EC2_IPV4_LOCAL}:2380" \
  --discovery-srv="${var.dns_zone}" \
  --initial-cluster-token="${var.dns_zone}" \
  --initial-cluster-state="new"
EOF
}

data "ignition_systemd_unit" "k8s-master-kubelet" {
  name    = "kubelet.service"
  enabled = true

  content = <<EOF
[Service]
Environment=KUBELET_IMAGE_TAG=v'"${var.kube_version}"'_coreos.0
Environment="RKT_RUN_ARGS=--uuid-file-save=/var/run/kubelet-pod.uuid \
  --volume var-log,kind=host,source=/var/log \
  --mount volume=var-log,target=/var/log \
  --volume dns,kind=host,source=/etc/resolv.conf \
  --mount volume=dns,target=/etc/resolv.conf \
  --volume cni-bin,kind=host,source=/opt/cni/bin \
  --mount volume=cni-bin,target=/opt/cni/bin \
  --volume etc-cni,kind=host,source=/etc/cni/net.d \
  --mount volume=etc-cni,target=/etc/cni/net.d"
ExecStartPre=/usr/bin/mkdir -p /etc/cni/net.d
ExecStartPre=/bin/bash -c ' \\
  if [[ \$(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]]; then \\
    /bin/mount bpffs /sys/fs/bpf -t bpf; \\
  fi'
ExecStartPre=/usr/bin/mkdir -p /opt/cni/bin
ExecStartPre=/usr/bin/mkdir -p /etc/kubernetes/manifests
ExecStartPre=/usr/bin/mkdir -p /var/log/containers
ExecStartPre=-/usr/bin/rkt rm --uuid-file=/var/run/kubelet-pod.uuid
ExecStart=/usr/lib/coreos/kubelet-wrapper \
  --api-servers=http://127.0.0.1:8080 \
  --register-schedulable=false \
  --node-labels node-role.kubernetes.io/apiserver \
  --cni-conf-dir=/etc/cni/net.d \
  --network-plugin=cni \
  --container-runtime=docker \
  --allow-privileged=true \
  --pod-manifest-path=/etc/kubernetes/manifests \
  --cluster-dns=${var.dns_service_ip} \
  --cluster-domain=cluster.local
ExecStop=-/usr/bin/rkt stop --uuid-file=/var/run/kubelet-pod.uuid
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

data "ignition_systemd_unit" "k8s-master-conntrack" {
  name    = "increase-nfconntrack-connections.service"
  enabled = true

  content = <<EOF
[Unit]
Description=Increase the number of connections in nf_conntrack. default 65536

[Install]
WantedBy=multi-user.target

[Service]
Type=oneshot
ExecStartPre=/usr/sbin/modprobe nf_conntrack
ExecStart=/bin/sh -c 'sysctl -w net.netfilter.nf_conntrack_max=262144'
EOF
}

data "ignition_systemd_unit" "k8s-download-cfssl" {
  name    = "download-cfssl.service"
  enabled = true

  content = <<EOF
[Unit]
Description=Download cfssl
ConditionFileNotEmpty=!/usr/local/bin/cfssl
ConditionFileNotEmpty=!/usr/local/bin/cfssljson

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/curl -L -o /usr/local/bin/cfssl https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
ExecStartPre=/usr/bin/curl -L -o /usr/local/bin/cfssljson https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
ExecStart=/usr/bin/chmod +x /usr/local/bin/cfssl /usr/local/bin/cfssljson

[Install]
WantedBy=multi-user.target
EOF
}

# I don't like this method currently... ideas on how to do it differently
# just lacking motivation to change this up
data "ignition_systemd_unit" "k8s-download-pki" {
  name    = "download-pki-ca.service"
  enabled = true

  content = <<EOF
[Unit]
Description=Download PKI CA
ConditionFileNotEmpty=!/etc/cfssl/ca.pem
ConditionFileNotEmpty=!/etc/cfssl/ca-key.pem
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/rkt run \
  --net=host \
  --trust-keys-from-https \
  --volume=dns,kind=host,source=/etc/resolv.conf,readOnly=true --mount volume=dns,target=/etc/resolv.conf \
  --volume=ssl,kind=host,source=/etc/cfssl,readOnly=false --mount=volume=ssl,target=/etc/cfssl \
  quay.io/coreos/awscli -- aws s3 cp s3://${var.k8s-ca-bucket}/ca/public/ca.pem /etc/cfssl/
ExecStart=/usr/bin/rkt run \
  --net=host \
  --trust-keys-from-https \
  --volume=dns,kind=host,source=/etc/resolv.conf,readOnly=true --mount volume=dns,target=/etc/resolv.conf \
  --volume=ssl,kind=host,source=/etc/cfssl,readOnly=false --mount=volume=ssl,target=/etc/cfssl \
  quay.io/coreos/awscli -- aws s3 cp s3://${var.k8s-ca-bucket}/ca/private/ca-key.pem /etc/cfssl/
EOF
}

data "ignition_systemd_unit" "k8s-download-pub-ca" {
  name    = "download-pub-ca.service"
  enabled = true

  content = <<EOF
[Unit]
Description=Download Pub CA Key
ConditionFileNotEmpty=!/etc/kubernetes/ssl/ca.pem
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/rkt run \
  --net=host \
  --trust-keys-from-https \
  --volume=dns,kind=host,source=/etc/resolv.conf,readOnly=true --mount volume=dns,target=/etc/resolv.conf \
  --volume=ssl,kind=host,source=/etc/cfssl,readOnly=false --mount=volume=ssl,target=/etc/cfssl \
  quay.io/coreos/awscli -- aws s3 cp s3://${var.k8s-ca-bucket}/ca/public/ca.pem /etc/kubernetes/ssl/
EOF
}

data "ignition_file" "k8s-master-hostname" {
  count      = "${length(var.subnets)}"
  filesystem = "root"
  path       = "/etc/hostname"
  mode       = 0644

  content {
    content = "${format("master%02d.%s", count.index + 1, var.dns_zone)}"
  }
}

data "ignition_file" "k8s-docker-logrotate" {
  filesystem = "root"
  path       = "/etc/logrotate.d/docker-containers"
  mode       = 0644

  content {
    content = <<EOF
/var/lib/docker/containers/*/*.log {
  rotate 7
  daily
  compress
  size=1M
  missingok
  delaycompress
  copytruncate
}
EOF
  }
}

data "ignition_file" "k8s-kubeproxy" {
  filesystem = "root"
  path       = "/etc/kubernetes/manifests/kube-proxy.yml"
  mode       = 0644

  content {
    content = <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kube-proxy
  namespace: kube-system
spec:
  hostNetwork: true
  containers:
  - name: kube-proxy
    image: quay.io/coreos/hyperkube:v${var.kube_version}_coreos.0
    command:
    - /hyperkube
    - proxy
    - --kubeconfig=/etc/kubernetes/kubeconfig.yml
    - --master=https://apiserver.${ var.dns_zone }:6443
    securityContext:
      privileged: true
    volumeMounts:
      - mountPath: /etc/ssl/certs
        name: "ssl-certs"
      - mountPath: /etc/kubernetes/kubeconfig.yml
        name: "kubeconfig"
        readOnly: true
      - mountPath: /etc/kubernetes/ssl
        name: "etc-kube-ssl"
        readOnly: true
      - mountPath: /var/run/dbus
        name: dbus
        readOnly: false
  volumes:
    - name: "ssl-certs"
      hostPath:
        path: "/usr/share/ca-certificates"
    - name: "kubeconfig"
      hostPath:
        path: "/etc/kubernetes/kubeconfig.yml"
    - name: "etc-kube-ssl"
      hostPath:
        path: "/etc/kubernetes/ssl"
    - name: dbus
      hostPath:
        path: "/var/run/dbus"
EOF
  }
}

data "ignition_file" "k8s-kube-scheduler" {
  filesystem = "root"
  path       = "/etc/kubernetes/manifests/kube-scheduler.yaml"
  mode       = 0644

  content {
    content = <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kube-scheduler
  namespace: kube-system
spec:
  hostNetwork: true
  containers:
  - name: kube-scheduler
    image: quay.io/coreos/hyperkube:v${var.kube_version}_coreos.0
    command:
    - /hyperkube
    - scheduler
    - --master=http://127.0.0.1:8080
    - --leader-elect=true
    resources:
      requests:
        cpu: 100m
    livenessProbe:
      httpGet:
        host: 127.0.0.1
        path: /healthz
        port: 10251
      initialDelaySeconds: 15
      timeoutSeconds: 15
EOF
  }
}

data "ignition_file" "k8s-kubecontroller" {
  filesystem = "root"
  path       = "/etc/kubernetes/manifests/kube-controller.yaml"
  mode       = 0644

  content {
    content = <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
spec:
  hostNetwork: true
  containers:
  - name: kube-controller-manager
    image: quay.io/coreos/hyperkube:v${var.kube_version}_coreos.0
    command:
    - /hyperkube
    - controller-manager
    - --master=http://127.0.0.1:8080
    - --leader-elect=true
    - --cloud-provider=aws
    - --service-account-private-key-file=/etc/kubernetes/ssl/apiserver-key.pem
    - --root-ca-file=/etc/kubernetes/ssl/ca.pem
    resources:
      requests:
        cpu: 200m
    livenessProbe:
      httpGet:
        host: 127.0.0.1
        path: /healthz
        port: 10252
      initialDelaySeconds: 15
      timeoutSeconds: 15
    volumeMounts:
    - mountPath: /etc/kubernetes/ssl
      name: ssl-certs-kubernetes
      readOnly: true
    - mountPath: /etc/ssl/certs
      name: ssl-certs-host
      readOnly: true
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/kubernetes/ssl
    name: ssl-certs-kubernetes
  - hostPath:
      path: /usr/share/ca-certificates
    name: ssl-certs-host
EOF
  }
}

data "ignition_file" "fetch-from-s3" {
  filesystem = "root"
  path       = "/opt/bin/fetch-from-s3"
  mode       = 0755

  content {
    content = <<EOF
#!/bin/bash -e
until /usr/bin/rkt run \
  --net=host \
  --trust-keys-from-https \
  --volume=dns,kind=host,source=/etc/resolv.conf,readOnly=true --mount volume=dns,target=/etc/resolv.conf \
  --volume=ssl,kind=host,source=/etc/kubernetes/ssl,readOnly=false --mount=volume=ssl,target=/etc/kubernetes/ssl \
  quay.io/coreos/awscli -- aws s3 cp s3://${var.k8s-ca-bucket}/$2 /etc/kubernetes/ssl
do
  echo "retrying"
  sleep 5.2
done
echo "✓"
EOF
  }
}

data "ignition_file" "set-hostname" {
  filesystem = "root"
  path       = "/opt/bin/setHostname"
  mode       = 0775

  content {
    content = <<EOF
#!/bin/bash -e
ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
HOST_PREFIX="ip-"
HOST_POST=`echo $private_ipv4 | awk 'BEGIN { OFS = "-"; FS = "." } { print $1, $2, $3, $4 }'`
# Systemd Override Hostname
/usr/bin/hostnamectl set-hostname $HOST_PREFIX$HOST_POST
# Update EC2 Name Tag
until /usr/bin/rkt run \
  --net=host \
  --trust-keys-from-https \
  --volume=dns,kind=host,source=/etc/resolv.conf,readOnly=true --mount volume=dns,target=/etc/resolv.conf \
  --volume=ssl,kind=host,source=/etc/kubernetes/ssl,readOnly=false --mount=volume=ssl,target=/etc/kubernetes/ssl \
  quay.io/coreos/awscli -- aws ec2 create-tags --region ${var.aws_region} --resources $ID --tags Key=Name,Value=$HOST_PREFIX$HOST_POST
do
  echo "retrying"
  sleep 5.2
done
echo "✓"
EOF
  }
}

data "ignition_file" "wait-apiserver" {
  filesystem = "root"
  path       = "/opt/bin/wait-for-apiserver"
  mode       = 0775

  content {
    content = <<EOF
#!/bin/bash -e
until curl --insecure https://apiserver.${ var.dns_zone }:6443/ &>/dev/null
do
  echo "waiting for apiserver..."
  sleep 5.2
done
echo "✓"
EOF
  }
}

data "ignition_file" "create-certificates" {
  filesystem = "root"
  path       = "/opt/bin/create-certificates"
  mode       = 0775

  content {
    content = <<ENDOFFILE
#!/bin/bash -ex
OUTDIR=/etc/kubernetes/ssl
function error {
  echo "✗ Error on line $1"'!'
  exit 1
}
trap 'error $${LINENO}' ERR
until printf "." && curl -d '{"label":"primary"}' http://apiserver.${ var.dns_zone }:8888/api/v1/cfssl/info &>/dev/null
do sleep 5.2; done; echo "✓"
DNS1="kubernetes"
DNS2="kubernetes.default"
DNS3="kubernetes.default.svc"
DNS4="kubernetes.default.svc.cluster.local"
DEFAULT_HOSTS="$DNS1,$DNS2,$DNS3,$DNS4,127.0.0.1"
function csr {
  cat <<EOF
{"CN":"$1","hosts":[""],"key":{"algo":"rsa","size":2048}}
EOF
}
function generate {
  CN=$1
  PROFILE=$2
  HOSTS=$3
  echo "$(csr $CN)" \
    | /opt/bin/cfssl gencert \
      -remote=apiserver.${ var.dns_zone }:8888 \
      -profile=$PROFILE \
      -hostname="$HOSTS" - \
    | /opt/bin/cfssljson -bare $CN

  chmod 0644 $${CN}.pem $${CN}-key.pem
}

mkdir -p $OUTDIR && cd $OUTDIR

generate apiserver client "$${DEFAULT_HOSTS},*.*.compute.internal,*.ec2.internal"
ENDOFFILE
  }
}

data "ignition_config" "k8s-master" {
  count = "${length(var.subnets)}"

  files = [
    "${data.ignition_file.k8s-master-hostname.*.id[count.index]}",
    "${data.ignition_file.k8s-docker-logrotate.id}",
    "${data.ignition_file.k8s-kube-scheduler.id}",
    "${data.ignition_file.k8s-kubeproxy.id}",
    "${data.ignition_file.k8s-kubecontroller.id}",
    "${data.ignition_file.fetch-from-s3.id}",
    "${data.ignition_file.set-hostname.id}",
    "${data.ignition_file.wait-apiserver.id}",
    "${data.ignition_file.create-certificates.id}",
  ]

  systemd = [
    "${data.ignition_systemd_unit.k8s-master.*.id[count.index]}",
    "${data.ignition_systemd_unit.k8s-master-conntrack.id}",
    "${data.ignition_systemd_unit.k8s-master-kubelet.id}",
    "${data.ignition_systemd_unit.k8s-download-cfssl.id}",
    "${data.ignition_systemd_unit.k8s-download-pub-ca.id}",
  ]
}

data "aws_ami" "containeros_stable" {
  most_recent = true

  filter {
    name   = "name"
    values = ["CoreOS-stable*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "owner-id"
    values = ["595879546273"] # CoreOS
  }
}

resource "aws_security_group" "k8s-master-sg" {
  name        = "${var.tag_costcenter}-master"
  description = "Kuberenetes Master APIs"
  vpc_id      = "${var.vpc_id}"

  # Allow Communication to Self
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  # Allow SSH from Office
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["50.235.45.162/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags {
    Name = "${format("%s-k8s-master-sg", var.tag_costcenter)}"
  }
}

# K8s Masters
resource "aws_instance" "k8s-masters" {
  count = "${length(var.subnets)}"

  ami                    = "${data.aws_ami.containeros_stable.id}"
  instance_type          = "${var.master_ec2_instance_type}"
  ebs_optimized          = "${var.master_ebs_optimized}"
  key_name               = "${var.key_name}"
  vpc_security_group_ids = ["${aws_security_group.k8s-master-sg.id}"]
  subnet_id              = "${element(var.subnets, count.index)}"
  iam_instance_profile   = "${aws_iam_instance_profile.k8s-master-host.id}"
  private_ip             = "${cidrhost(element(var.subnets_cidr_blocks, count.index), 10)}"
  user_data              = "${element(data.ignition_config.k8s-master.*.rendered, count.index)}"

  #user_data              = "${element(data.template_file.master-userdata.*.rendered, count.index)}"

  root_block_device {
    volume_type = "${var.master_volume_type}"
    volume_size = "${var.master_volume_size}"
  }
  tags {
    Name        = "${format("master%02d", count.index + 1)}"
    cost_center = "${var.tag_costcenter}"
    env         = "${var.tag_env}"
    role        = "${var.tag_costcenter}-master"
    prom_env    = "${var.tag_costcenter}"
  }
  lifecycle {
    ignore_changes = ["ami"]
  }
}

resource "aws_route53_record" "k8s-master" {
  count = "${length(var.subnets)}"

  zone_id = "${var.zone_id[0]}"
  name    = "${format("master%02d", count.index + 1)}"
  type    = "A"
  ttl     = 30
  records = ["${element(aws_instance.k8s-masters.*.private_ip, count.index)}"]
}

resource "aws_route53_record" "k8s-etcd-server-discovery" {
  zone_id = "${var.zone_id[0]}"
  type    = "SRV"
  ttl     = "60"
  name    = "_etcd-server._tcp"
  records = ["${formatlist("0 0 2380 %s.", aws_route53_record.k8s-master.*.fqdn)}"]
}

resource "aws_route53_record" "k8s-etcd-client-discovery" {
  zone_id = "${var.zone_id[0]}"
  type    = "SRV"
  ttl     = "60"
  name    = "_etcd-client._tcp"
  records = ["${formatlist("0 0 2379 %s.", aws_route53_record.k8s-master.*.fqdn)}"]
}

resource "aws_lb" "k8s-master-internal-nlb" {
  name               = "${var.name}-apiserver-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = ["${var.subnets}"]

  enable_deletion_protection       = false
  enable_cross_zone_load_balancing = true

  tags {
    env         = "${var.tag_env}"
    cost_center = "${var.tag_costcenter}"
  }
}

# data "aws_lb_listener" "k8s-master-internal-nlb-listener" {
#   load_balancer_arn = "${aws_lb.k8s-master-internal-nlb.arn}"
#   port              = "6443"
#   protocol          = "tcp"
#
#   default_action {
#     target_group_arn = "${}"
#     type             = "forward"
#   }
# }

resource "aws_lb" "k8s-master-external-nlb" {
  name               = "${var.name}-apiserver-ext-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = ["${var.subnets}"]

  enable_deletion_protection       = false
  enable_cross_zone_load_balancing = true

  tags {
    env         = "${var.tag_env}"
    cost_center = "${var.tag_costcenter}"
  }
}

# resource "aws_route53_record" "k8s-master-internal-nlb" {
#   zone_id = "${var.zone_id[0]}"
#   type    = "CNAME"
#   name    = "apiserver.${var.dns_zone}."
#   records = [""]
# }

# resource "aws_autoscaling_group" "k8s-masters" {
#   name                 = "${format("%s-k8s-master%02d", var.tag_costcenter, count.index + 1)}"
#   launch_configuration = "${element(aws_launch_configuration.k8s-master-config.*.name, count.index)}"
#   force_delete         = true
#   min_size             = 1
#   max_size             = 1
#
#   count = "${length(var.subnets)}"
#
#   vpc_zone_identifier = ["${element(var.subnets, count.index)}"]
#
#   tags = [
#     {
#       key                 = "cost_center"
#       value               = "${var.tag_costcenter}"
#       propagate_at_launch = true
#     },
#     {
#       key                 = "env"
#       value               = "${var.tag_env}"
#       propagate_at_launch = true
#     },
#     {
#       key                 = "role"
#       value               = "${var.tag_master_role}"
#       propagate_at_launch = true
#     },
#     {
#       key                 = "KubernetesCluster"
#       value               = "bricks"
#       propagate_at_launch = true
#     },
#     {
#       key                 = "prom_env"
#       value               = "${var.tag_costcenter}"
#       propagate_at_launch = true
#     },
#   ]
#
#   lifecycle {
#     create_before_destroy = true
#   }
# }
#
# resource "aws_launch_configuration" "k8s-master-config" {
#   count         = "${length(var.subnets)}"
#   name_prefix   = "${format("%s-master%02d-", var.tag_costcenter, count.index + 1)}"
#   image_id      = "${data.aws_ami.containeros_stable.id}"
#   instance_type = "t2.large"
#   key_name      = "${var.ssh_key_name}"
#   ebs_optimized = "false"
#
#   # Storage
#   root_block_device {
#     volume_size = "100"
#     volume_type = "gp2"
#   }
#
#   # Security
#   iam_instance_profile = "${aws_iam_instance_profile.k8s-master-host.id}"
#   security_groups      = ["${aws_security_group.k8s-master-sg.id}"]
#
#   # UserData
#   user_data = "${element(data.template_file.master-userdata.*.rendered, count.index)}"
#
#   lifecycle {
#     create_before_destroy = true
#   }
# }

resource "aws_iam_role_policy" "k8s-master-host-policy" {
  name = "${var.name}-master-host-policy"
  role = "${aws_iam_role.k8s-master-role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
        "Effect": "Allow",
        "Action": "ec2:Describe*",
        "Resource": "*"
    },
    {
        "Effect": "Allow",
        "Action": "ec2:AttachVolume",
        "Resource": "*"
    },
    {
        "Effect": "Allow",
        "Action": "ec2:DetachVolume",
        "Resource": "*"
    },
    {
        "Effect": "Allow",
        "Action": "ec2:CreateTags",
        "Resource": "*"
    },
    {
        "Effect": "Allow",
        "Action": [
            "ecr:GetAuthorizationToken",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:GetRepositoryPolicy",
            "ecr:DescribeRepositories",
            "ecr:ListImages",
            "ecr:BatchGetImage"
        ],
        "Resource": "*"
    },
    {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::${var.k8s-ca-bucket}/public/ca.pem"
    },
    {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::${var.k8s-ca-bucket}/private/ca-key.pem"
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "k8s-master-host" {
  name = "${var.name}-k8s-master-profile"
  role = "${aws_iam_role.k8s-master-role.name}"
}

resource "aws_iam_role" "k8s-master-role" {
  name = "${var.name}-k8s-master-role"
  path = "/"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}
