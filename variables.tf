variable "project_id" {
  type        = string
  description = "The GCP project ID to deploy resources into."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "The GCP region for resources."
}

variable "org_mappings" {
  type        = map(string)
  description = "Mapping of cluster/namespace to org. Keys are 'cluster/namespace', values are org names."
  default = {
    "cluster-2/default" = "ortelius"
    "cluster-2/deployhub"    = "deployhub"
  }
}
