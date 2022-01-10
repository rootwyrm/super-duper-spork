provider "aws" {
  region = local.region 
}

locals {
  name              = "voith-$"
  cluster_version   = 1.21
  region            = "us-east-2"

  alpine_ami        = "ami-PLACEHOLDER"
  ubuntu_ami = [{
    us-east-1 = ["ami-06992628e0a8e044c"]
    us-east-2 = ["ami-08b56b59adf9cd137"]
  }]

  tags = {
    Environment = "Demo"
    GithubRepo  = "voith"
    GithubOrg   = "rootwyrm"
  }

  ## Define subnets up here. Shh.
  private_subnets = ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"]
  public_subnets  = ["10.1.1.0/24", "10.2.1.0/24", "10.3.1.0/24"]
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "18.0.5"

  cluster_name      = local.name
  cluster_version   = local.cluster_version
  cluster_endpoint_private_access   = true
  cluster_endpoint_public_access    = true

  ## Set reasonable values here
  cluster_addons = {
    coredns = {
      resolve_conflicts   = "OVERWRITE"
    }
    vpc-cni = {
      resolve_conflicts   = "OVERWRITE"
    }
  }

  ## TODO: provider_key_arn should be an external variable
  cluster_encryption_config = [{
    provider_key_arn  = aws_kms_key.eks.arn
    resources         = ["secrets"]
  }]

  enable_irsa   = true
 
  ## TODO: should be external variable switched around environment/region
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets


  self_managed_node_group_defaults = {
    vpc_security_group_ids       = [aws_security_group.additional.id]
    iam_role_additional_policies = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
  }

  self_managed_node_groups = {
    spot = {
      instance_type = "t3a.small"
      instance_market_options = {
        market_type = "spot"
      }

      ## TODO: uses a file that I haven't written
      pre_bootstrap_user_data = file("${path.module}/bootstrap.pre")

      ## TODO: uses a file that I haven't written
      ## NOTE: could probably be done as a local_file data ./env.userdata
      #user_bootstrap_user_data = file("${path.module}/${local.environment}.userdata")
      user_bootstrap_user_data = file("${path.module}/userdata")
    }
  }

  eks_managed_node_group_defaults = {
    ## These are nodes, so, kind of stuck.
    ami_type      = "AL2_x86_64"
    disk_size     = 75
    instance_types  = ["t3a.small", "t3a.medium", "t3a.large", "t3a.xlarge" ]
    vpc_security_group_ids  = [aws_security_group.additional.id]
  }

  eks_managed_node_groups = {
    ## FYI: integers must be quoted always
    "00" = {}
    "01" = {
      min_size      = 1
      max_size      = 4
      desired_size  = 1

      instance_types  = ["t3a.small"]
      capacity_type   = "SPOT"
      labels = {
        Environment   = local.tags.Environment
        Task          = "Management"
      }
    }
    "02" = {
      min_size      = 2
      max_size      = 8
      desired_size  = 2

      instance_types  = ["t3a.small"]
      capacity_type   = "SPOT"
      labels = {
        Environment   = local.tags.Environment
        Task          = "Processor"
      }
      update_config = {
        ## Don't go below min_size even mid-upgrade.
        max_unavailable_percentage  = 50
      }
    }
    tags = {
      Terraform   = "Demo"
    }
  }
}

## Define the aws-auth
data "aws_eks_cluster_auth" "this" {
  name = module.eks.cluster_id
}

## XXX: Just outright stole this, because I haven't done the configmap this way
## before.
locals {
  kubeconfig = yamlencode({
    apiVersion      = "v1"
    kind            = "Config"
    current-context = "terraform"
    clusters = [{
      name = module.eks.cluster_id
      cluster = {
        certificate-authority-data = module.eks.cluster_certificate_authority_data
        server                     = module.eks.cluster_endpoint
      }
    }]
    contexts = [{
      name = "terraform"
      context = {
        cluster = module.eks.cluster_id
        user    = "terraform"
      }
    }]
    users = [{
      name = "terraform"
      user = {
        token = data.aws_eks_cluster_auth.this.token
      }
    }]
  })

  ## The actual configmap yaml
  ## XXX: This is missing other typically needed ARNs like S3/Glacier
  aws_auth_configmap_yaml = <<-EOT
  ${chomp(module.eks.aws_auth_configmap_yaml)}
      - rolearn: ${module.eks_managed_node_group.iam_role_arn}
        username: system:node:{{EC2PrivateDNSName}}
        groups:
          - system:bootstrappers
          - system:nodes
      - rolearn: ${module.self_managed_node_group.iam_role_arn}
        username: system:node:{{EC2PrivateDNSName}}
        groups:
          - system:bootstrappers
          - system:nodes
  EOT
}

## XXX: I omitted the kubectl portion because there's too many different ways
## to do it, and I'm used to:
## awscli update-cluster-version --name cluster --client-request-token $AWSTOKEN --kubernetes-version 1.21 --generate-cli-skeleton 
## ... then validating the JSON and re-running with --cli-input-json 

## Node group management
module "eks_managed_node_group" {
  source = "terraform-aws-modules/eks/aws//modules/eks-managed-node-group"

  name            = "separate-eks-mng"
  cluster_name    = module.eks.cluster_id
  cluster_version = local.cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  tags = merge(local.tags, { Separate = "eks-managed-node-group" })
}
module "self_managed_node_group" {
  source = "terraform-aws-modules/eks/aws//modules/self-managed-node-group"

  name                = "separate-self-mng"
  cluster_name        = module.eks.cluster_id
  cluster_version     = local.cluster_version
  cluster_endpoint    = module.eks.cluster_endpoint
  cluster_auth_base64 = module.eks.cluster_certificate_authority_data

  instance_type = "t3a.small"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  vpc_security_group_ids = [
    module.eks.cluster_primary_security_group_id,
    module.eks.cluster_security_group_id,
  ]

  tags = merge(local.tags, { Separate = "self-managed-node-group" })
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  name = local.name
  ## XXX: I don't believe this cidr has to be this broad.
  cidr = "10.0.0.0/16"

  azs             = ["${local.region}a", "${local.region}b", "${local.region}c"]
  ## TODO: would prefer to use a /25 or smaller unless we know there will be
  ## more than 128 distinct IP endpoints. Costs a few 10net addresses (-4 per 
  ## /24) but provides better segmentation for security.
  private_subnets = ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"]
  public_subnets  = ["10.1.1.0/24", "10.2.1.0/24", "10.3.1.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/elb"              = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.name}" = "shared"
    "kubernetes.io/role/internal-elb"     = 1
  }

  tags = local.tags
}

resource "aws_security_group" "additional" {
  name_prefix = "${local.name}-additional"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    ## XXX: the example for this is just HORRIBLE. Allows all of 10.0.0.0/8!?
    ## That's a terrible idea! All of 172.16.0.0/12? Also unnecessary!
    ## TODO: should use a private API endpoint
    cidr_blocks = [
      ## TODO: I couldn't get this working in time; missing an iterator
      #{permit_private = local.private_subnets},
      ## FYI: keep scope NARROW!!
      "10.1.0.0/24",
      "10.2.0.0/24",
      "10.3.0.0/24",
      "172.16.0.0/12",
      "192.168.0.0/16",
    ]
  }

  tags = local.tags
}

resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = local.tags
}
