provider "aws" {
  alias  = "virginia"
  region = "us-east-1"
}


terraform {
   required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.17.1"
    }
  }
  backend "remote" {
    organization = "sachin1991"

    workspaces {
      name = "sachin-test"
    }
  }
}

