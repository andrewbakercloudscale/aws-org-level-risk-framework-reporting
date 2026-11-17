# Access Graph

A part of the Cloud Assurance report. It answers one question for any account in the scan: **what can
reach it?** Other accounts in the organisation, accounts outside it, identity providers, anyone, and
the internet, over the network and through IAM. Pick an account, how many hops out to follow (1 to 5)
and the direction:

- **What can reach it**: every source with a path in, and the sources that can reach those, and so on;
- **What it can reach**: the same walk outwards;
- **Both**.

![Access Graph: what can reach legacy-batch-prod, two hops out, in the demo organisation](images/access-graph.png)

Network and IAM paths can be shown together or on their own. Select an account in the graph or in
"Most reachable accounts" to put it at the centre. Hover a line for the rules behind it.

## What is read

Read with the Cloud Assurance checks in each account and region, read-only. No new scan option: a scan
with Cloud Assurance ticked has the graph.

| Path | Edge | Read with |
|---|---|---|
| Transit gateway | Every account attached to a gateway reaches every other account on it | `ec2:DescribeTransitGatewayAttachments` |
| VPC peering | Both ways between the requester and accepter accounts (active peerings only) | `ec2:DescribeVpcPeeringConnections` |
| PrivateLink | A principal allowed on an endpoint service reaches its owner; an endpoint to another account's service reaches that account | `ec2:DescribeVpcEndpointServiceConfigurations`, `ec2:DescribeVpcEndpointServicePermissions`, `ec2:DescribeVpcEndpoints` |
| Security group reference | A group in use admits another account's group | `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces` |
| Security group range | A group in use admits a range that overlaps another scanned account's VPC, **and** a route exists between the two (a shared transit gateway or a peering) | as above, plus `ec2:DescribeVpcs` |
| Open to the internet | A group in use admits `0.0.0.0/0` | as above |
| Role trust | A role trusts a principal outside the account | `iam:GetAccountAuthorizationDetails` |
| Bucket policy | A bucket policy allows a principal outside the account | `s3:GetBucketPolicy` |

A security-group range no scanned VPC owns goes to **Other private networks** (on-premises, partners,
accounts not in the scan) when it is private, and **Specific internet addresses** when it is public.
A trust or grant of `*` is **Anyone**, unless a condition limits it to the organisation
(`aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`: **Any account in the organisation**) or names accounts
(`aws:PrincipalAccount`, `aws:PrincipalArn`: those accounts). Service principals and the account's own
principals are not paths. Role trusts note when they need an external id.

Only account ids, role and bucket names, CIDRs, ports and resource ids are kept.

## Hops

A hop is one step from a source to what it reaches. A transit gateway is passed through, not counted:
two accounts on one gateway are one hop apart, as they are for traffic. Gateways are drawn as diamonds
with dashed lines to their members.

## What it does not evaluate

An edge means a path exists, not that it is used, and not that it is wrong. Route tables, network ACLs,
transit gateway route tables, SCPs, RCPs, permission boundaries and session policies are not evaluated,
so a drawn path may be blocked further along. The flow logs that show which paths carry traffic are the
job of [sg-tightener](https://github.com/andrewbakercloudscale/sg-tightener), which narrows the broad
security-group ranges this graph exposes to the addresses actually seen.

Each list is kept to 1,000 entries per account and region; the report says when one was cut.
