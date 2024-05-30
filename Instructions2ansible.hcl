//main.tf
//multiple instances

provider "aws" {
  region = "us-west-2"
}

# Define the number of instances to create
variable "instance_count" {
  default = 3
}

# Define the instance configurations
resource "aws_instance" "kali" {
  count = var.instance_count
  ami           = "ami-12345678" # Replace with the Kali Linux AMI ID
  instance_type = "t2.micro"

  key_name = "my-key-pair" # Replace with your key pair

  tags = {
    Name = "KaliLinuxInstance-${count.index}"
  }

  # Provisioners for instance setup
  provisioner "local-exec" {
    command = "ansible-playbook -i ${self.public_ip}, -u ec2-user --private-key /path/to/my-key-pair.pem setup_kali.yml"
  }

  connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = file("/path/to/my-key-pair.pem")
    host        = self.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y ansible",
    ]
  }

  # Error handling
  lifecycle {
    ignore_changes = [
      tags # Ignore changes to instance tags
    ]
  }
}