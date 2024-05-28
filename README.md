# Encrypted Traffic Orchestrator AWS Examples

This repository contains AWS samples to demonstrate how to create a Mira ETO on AWS.

| Examples | Details |
| ----------|---------|
| Spokes (Endpoints) |
| [applications-spoke](1az-applications-spoke)| a Nginx and Squid Proxy server with subnets setup to route through a Security GWLBe |
| [3az-applications-spoke-nginx](3az-applications-spoke-nginx)| a Nginx server and Application Load Balancer distributed over 3AZs and setup to route through a Security GWLBe |
| OpenSource Tools |
| [eto-security-onion](1az-security-eto-security-onion) | Mira ETO with a GWLB and Security Onion Threat Hunting Platform |
| [eto-selks](1az-security-eto-selks) | Mira ETO with a GWLB and SELKS Security Monitoring Platform |
| Commercial Tools |
| [eto-corelight](1az-security-eto-corelight) | Mira ETO with a GWLB and Corelight Cloud Sensor |
| [eto-stamus-ssp](1az-security-eto-stamus-ssp) | Mira ETO with a GWLB and Stamus Security Platform (SSP) |
| [eto-trellix-nx](1az-security-eto-trellix-nx) | Mira ETO with a GWLB and Trellix Network Security (NX) |
| Autoscaling ETOs with Suricata Tool |
| [autoscaling-api](3az-security-eto-asg-api-suricata) | Mira ETO autoscaled using IaC REST API and feeding Suricata Tools |

For ETO on AWS product information visit [Mira Website](https://mirasecurity.com/how-mira-works/eto-aws/)

For ETO AMIs visit our [AWS Marketplace listing](https://aws.amazon.com/marketplace/seller-profile?id=seller-vh5fkitegcazg)

For ETO administrator documentation or support please visit [Mira Support Site](https://support.mirasecurity.com)

Note: These are all samples and may not be suitable for production use.
