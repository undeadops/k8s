# resource "aws_iam_role_policy" "k8s-worker-host-policy" {
#   name = "${var.name}-worker-host-policy"
#   role = "${aws_iam_role.k8s-worker-role.id}"
#
#   policy = <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#         "Effect": "Allow",
#         "Action": "ec2:Describe*",
#         "Resource": "*"
#     },
#     {
#         "Effect": "Allow",
#         "Action": "ec2:AttachVolume",
#         "Resource": "*"
#     },
#     {
#         "Effect": "Allow",
#         "Action": "ec2:DetachVolume",
#         "Resource": "*"
#     },
#     {
#         "Effect": "Allow",
#         "Action": "ec2:CreateTags",
#         "Resource": "*"
#     },
#     {
#         "Effect": "Allow",
#         "Action": [
#             "ecr:GetAuthorizationToken",
#             "ecr:BatchCheckLayerAvailability",
#             "ecr:GetDownloadUrlForLayer",
#             "ecr:GetRepositoryPolicy",
#             "ecr:DescribeRepositories",
#             "ecr:ListImages",
#             "ecr:BatchGetImage"
#         ],
#         "Resource": "*"
#     },
#     {
#         "Effect": "Allow",
#         "Action": "s3:GetObject",
#         "Resource": "arn:aws:s3:::${var.k8s-ca-bucket}/public/ca.pem"
#     }
#   ]
# }
# EOF
# }

