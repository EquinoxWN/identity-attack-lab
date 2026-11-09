// Saved queries for BloodHound CE (Cypher tab) to explore the lab after ingesting
// bloodhound/model/*.json or a real collection from the lab. Not yet run against a live
// BloodHound CE instance in this repository (see docs/results/m1.md, "Not verified").

// 1. Shortest paths from Kerberoastable users to Domain Admins
MATCH p = shortestPath((u:User {hasspn: true})-[:MemberOf|AdminTo|HasSession|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AddMember|AllExtendedRights|DCSync*1..]->(g:Group))
WHERE g.objectid ENDS WITH '-512'
RETURN p;

// 2. Shortest paths from AS-REP roastable users to Domain Admins
MATCH p = shortestPath((u:User {dontreqpreauth: true})-[:MemberOf|AdminTo|HasSession|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AddMember|AllExtendedRights|DCSync*1..]->(g:Group))
WHERE g.objectid ENDS WITH '-512'
RETURN p;

// 3. Principals that can DCSync the domain
MATCH p = (n)-[:DCSync]->(d:Domain)
RETURN p;

// 4. Computers where a Domain Admin has a session
MATCH p = (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512'
RETURN p;
