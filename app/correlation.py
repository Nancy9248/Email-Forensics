"""
Identity Correlation and Attribution Support.
Builds a graph connecting sender DOMAINS and IPs across every case in
the database. Two entities are linked if they've ever appeared together
in the same case (e.g. domain X was sent from IP Y).

Why a graph matters here: a single new phishing domain with NO prior
history looks harmless in isolation. But if that domain's sending IP
was ALSO used by three other fake domains last week, the graph reveals
they're likely the same actor/campaign — a correlation a simple
"have we seen this domain before?" lookup would completely miss.
"""

import networkx as nx
from case_db import get_all_cases


def build_case_graph(cases):
    """
    Build an undirected graph: one node per domain, one node per IP,
    an edge between them for every case that links that domain to that IP.
    """
    graph = nx.Graph()

    for case in cases:
        domain = case.get("sender_domain")
        ip = case.get("originating_ip")

        if domain:
            graph.add_node(domain, type="domain")
        if ip:
            graph.add_node(ip, type="ip")

        if domain and ip:
            if graph.has_edge(domain, ip):
                graph[domain][ip]["weight"] += 1
                graph[domain][ip]["case_ids"].append(case["id"])
            else:
                graph.add_edge(domain, ip, weight=1, case_ids=[case["id"]])

    return graph


def find_correlations(sender_domain, originating_ip):
    """
    Given the domain and IP of a NEWLY analyzed email, check the case
    history graph for direct repeats and indirect links via shared
    infrastructure — catching campaigns that rotate domains but reuse
    the same sending IPs.
    """
    prior_cases = get_all_cases()
    if not prior_cases:
        return {
            "same_domain_count": 0,
            "same_ip_count": 0,
            "linked_entities": [],
            "is_repeat_offender": False,
        }

    graph = build_case_graph(prior_cases)

    same_domain_count = sum(1 for c in prior_cases if c.get("sender_domain") == sender_domain)
    same_ip_count = sum(1 for c in prior_cases if c.get("originating_ip") == originating_ip)

    linked_entities = set()
    exclude = {sender_domain, originating_ip}
    for entity in (sender_domain, originating_ip):
        if entity and graph.has_node(entity):
            nearby = nx.single_source_shortest_path_length(graph, entity, cutoff=2)
            for node in nearby:
                if node not in exclude:
                    linked_entities.add(node)

    return {
        "same_domain_count": same_domain_count,
        "same_ip_count": same_ip_count,
        "linked_entities": sorted(linked_entities),
        "is_repeat_offender": same_domain_count > 0 or same_ip_count > 0 or len(linked_entities) > 0,
    }

def get_campaign_groups():
    """
    Group all cases into CAMPAIGNS using connected components of the
    domain/IP graph: any set of domains and IPs that are all linked
    together (directly or via shared infrastructure) forms one campaign.
    Only returns groups with more than one distinct case.
    """
    cases = get_all_cases()
    if not cases:
        return []

    graph = build_case_graph(cases)
    case_lookup = {c["id"]: c for c in cases}

    campaigns = []
    for component in nx.connected_components(graph):
        case_ids_in_group = set()
        for node in component:
            for neighbor in graph.neighbors(node):
                edge_data = graph.get_edge_data(node, neighbor)
                if edge_data and "case_ids" in edge_data:
                    case_ids_in_group.update(edge_data["case_ids"])

        if len(case_ids_in_group) > 1:
            group_cases = [case_lookup[cid] for cid in case_ids_in_group if cid in case_lookup]
            domains = sorted({n for n in component if graph.nodes[n].get("type") == "domain"})
            ips = sorted({n for n in component if graph.nodes[n].get("type") == "ip"})
            campaigns.append({
                "domains": domains,
                "ips": ips,
                "case_count": len(group_cases),
                "cases": sorted(group_cases, key=lambda c: c["analyzed_at"], reverse=True),
                "max_score": max((c["fraud_score"] for c in group_cases), default=0),
            })

    campaigns.sort(key=lambda c: c["case_count"], reverse=True)
    return campaigns

if __name__ == "__main__":
    import json
    result = find_correlations("fake-bank-3.com", "45.142.212.61")
    print(json.dumps(result, indent=2))