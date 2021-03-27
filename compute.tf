terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "3.5.0"
    }
  }
}

# The location where we search for the key for the service account
variable "gcp_service_account_key" {
  type = string
  default = "~/serviceAccount/learning-gcp-course-3-ed375d8bcdbf.json"
}

# Get the ID of the project that we use from our service account key 
locals {
  key_data = jsondecode(file("${var.gcp_service_account_key}"))
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-c"
}

variable "gce_ssh_public_key_file" {
  type    = string
  default = "~/.ssh/ssh-key-ansible-sa.pub"
}

variable "gce_ssh_private_key_file" {
  type    = string
  default = "~/.ssh/ssh-key-ansible-sa"
}

provider "google" {
  credentials = "${file(var.gcp_service_account_key)}"
  project = local.key_data.project_id
  region  = var.region
  zone    = var.zone
}

resource "google_project_service" "service" {
  for_each = toset([
    "compute.googleapis.com",
    "cloudresourcemanager.googleapis.com"
  ])

  service = each.key

  project            = local.key_data.project_id
  disable_on_destroy = false
}

###############################################################################
# Networks
###############################################################################

# Create a VPC which will be our public network
resource "google_compute_network" "public-vpc" {
  name                    = "public-vpc"
  description             = "Public network, i.e. network to which all network interfaces with public IP addresses will be attached"
  auto_create_subnetworks = false
}

# Create a subnetwork within this VPC
resource "google_compute_subnetwork" "public-subnetwork" {
  name          = "public-subnetwork"
  ip_cidr_range = "192.168.100.0/24"
  network       = google_compute_network.public-vpc.self_link
  region = var.region
}

# Add firewall rules to allow incoming ICMP and SSH traffic
resource "google_compute_firewall" "public-firewall" {
  name    = "public-firewall"
  network = google_compute_network.public-vpc.self_link

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

}

# Create a VPC which will be our internal network
resource "google_compute_network" "internal-vpc" {
  name                    = "internal-vpc"
  description             = "Internal network"
  auto_create_subnetworks = false
}

# Create a subnetwork within this VPC
resource "google_compute_subnetwork" "internal-subnetwork" {
  name          = "internal-subnetwork"
  ip_cidr_range = "192.168.178.0/24"
  network       = google_compute_network.internal-vpc.self_link
  region        = var.region
  
}

# Add firewall rules to allow all incoming traffic on the internal network
resource "google_compute_firewall" "internal-firewall" {
  name    = "internal-firewall"
  network = google_compute_network.internal-vpc.self_link

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }
  
  source_ranges = ["192.168.178.0/24"]
  
}

# Add firewall rule to allow health check
data "google_compute_lb_ip_ranges" "ranges" {
}

resource "google_compute_firewall" "lb-firewall" {
  name    = "lb-firewall"
  network = google_compute_network.internal-vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = data.google_compute_lb_ip_ranges.ranges.network
  target_tags = [
    "instance-behind-lb",
  ]
}

# Add firewall rule to allow ssh to internal instances from GCP
resource "google_compute_firewall" "iap-firewall" {
  name    = "iap-firewall"
  network = google_compute_network.internal-vpc.self_link

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags = [
    "instance-behind-lb",
  ]
}

###############################################################################
# Jump host
###############################################################################

# Create an instance which will serve as our jump host. This instance will have two 
# network interfaces, one connected to the public network and one connected to the private
# network
resource "google_compute_instance" "jump-host" {
  name         = "jump-host"
  machine_type = "f1-micro"

  boot_disk {
    initialize_params {
      image = "centos-cloud/centos-8"
    }
  }
  # We add a user kovin with an SSH key
  metadata = {
    ssh-keys = "kovin:${file(var.gce_ssh_public_key_file)}"
  }

  
  network_interface {
    # This is the public interface, attached to our public network
    network       = google_compute_network.public-vpc.self_link
    subnetwork    = google_compute_subnetwork.public-subnetwork.self_link
    access_config {
    }
  }


  network_interface {
    # This is the internal interface, attached to our internal network
    network       = google_compute_network.internal-vpc.self_link
    subnetwork    = google_compute_subnetwork.internal-subnetwork.self_link
  }
  
  # remove sshguard at startup
  metadata_startup_script = "sudo apt-get -y remove sshguard"

  depends_on = [google_project_service.service]
} 

###############################################################################
# Target hosts
###############################################################################

resource "google_compute_instance" "target-host" {
  count        = 3
  project      = local.key_data.project_id
  zone         = var.zone
  name         = "target-host-${count.index}"
  machine_type = "f1-micro"

  tags = ["instance-behind-lb"]

  boot_disk {
    initialize_params {
      image = "centos-cloud/centos-8"
    }
  }

  metadata = {
    ssh-keys = "kovin:${file(var.gce_ssh_public_key_file)}"
  }

  network_interface {
    # This is the private interface, attached to our private network
    network       = google_compute_network.internal-vpc.self_link
    subnetwork    = google_compute_subnetwork.internal-subnetwork.self_link
    access_config {
    }
  }

  depends_on = [google_project_service.service]
}

###############################################################################
# Internal Load Balancer
###############################################################################
resource "google_compute_forwarding_rule" "default" {
  name   = "website-forwarding-rule"
  region = var.region

  load_balancing_scheme = "INTERNAL"
  backend_service       = google_compute_region_backend_service.backend.id
  all_ports             = true
  network               = google_compute_network.internal-vpc.name
  subnetwork            = google_compute_subnetwork.internal-subnetwork.name
}

resource "google_compute_instance_group" "webservers" {
  name        = "terraform-webservers"

  instances = [
    google_compute_instance.target-host[0].self_link,
    google_compute_instance.target-host[1].self_link,
    google_compute_instance.target-host[2].self_link
  ]

  named_port {
    name = "http"
    port = "8080"
  }

  named_port {
    name = "https"
    port = "8443"
  }

  zone = var.zone
}

resource "google_compute_region_backend_service" "backend" {
  name          = "website-backend"
  region        = var.region
  health_checks = [google_compute_health_check.hc.id]
  backend {
    group = google_compute_instance_group.webservers.id
  }
}

resource "google_compute_health_check" "hc" {
  name               = "check-website-backend"
  check_interval_sec = 1
  timeout_sec        = 1

  tcp_health_check {
    port = "80"
  }
}

###################################################################################
# Provide inventory data 
###################################################################################

output "inventory" {
  value = concat(
      [ {
        "groups"           : "['jump_host']",
        "name"             : "${google_compute_instance.jump-host.name}",
        "ip"               : "${google_compute_instance.jump-host.network_interface.0.access_config.0.nat_ip }",
        "ansible_ssh_user" : "kovin",
        "private_key_file" : "${var.gce_ssh_private_key_file}",
        "ssh_args"         : "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
      } ],
      [ {
        "groups"           : "['webservers']",
        "name"             : "${google_compute_instance.target-host[0].name}",
        "ip"               : "${google_compute_instance.target-host[0].network_interface.0.network_ip}",
        "ansible_ssh_user" : "kovin",
        "private_key_file" : "${var.gce_ssh_private_key_file}",
        "ssh_args"         : "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o \"ProxyCommand ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${var.gce_ssh_private_key_file} -W %h:%p kovin@${google_compute_instance.jump-host.network_interface.0.access_config.0.nat_ip}\""       
       }],
      [ {
        "groups"           : "['webservers']",
        "name"             : "${google_compute_instance.target-host[1].name}",
        "ip"               : "${google_compute_instance.target-host[1].network_interface.0.network_ip}",
        "ansible_ssh_user" : "kovin",
        "private_key_file" : "${var.gce_ssh_private_key_file}",
        "ssh_args"         : "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o \"ProxyCommand ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${var.gce_ssh_private_key_file} -W %h:%p kovin@${google_compute_instance.jump-host.network_interface.0.access_config.0.nat_ip}\""       
       }],
      [ {
        "groups"           : "['webservers']",
        "name"             : "${google_compute_instance.target-host[2].name}",
        "ip"               : "${google_compute_instance.target-host[2].network_interface.0.network_ip}",
        "ansible_ssh_user" : "kovin",
        "private_key_file" : "${var.gce_ssh_private_key_file}",
        "ssh_args"         : "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o \"ProxyCommand ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${var.gce_ssh_private_key_file} -W %h:%p kovin@${google_compute_instance.jump-host.network_interface.0.access_config.0.nat_ip}\""       
       }]
   )
}