import networkx as nx
import random
from typing import List, Tuple, Optional, Dict
import matplotlib.pyplot as plt
from collections import defaultdict

class ComprehensiveLightningNetwork:
    def __init__(self, num_nodes=25, initial_channel_capacity=1000, channel_density=0.3):
        self.num_nodes = num_nodes
        self.graph = nx.DiGraph()
        self.node_names = [f'Node_{i}' for i in range(num_nodes)]
        self.graph.add_nodes_from(self.node_names)
        self.scenario_results = defaultdict(list)
        
        # Create channels with realistic properties
        for i in range(num_nodes):
            for j in range(i+1, num_nodes):
                if random.random() < channel_density:
                    ab = random.randint(200, initial_channel_capacity-200)
                    ba = initial_channel_capacity - ab
                    fee = random.randint(1, 15)  # Higher fee range for realism
                    self.graph.add_edge(self.node_names[i], self.node_names[j], 
                                      balance=ab, fee=fee, capacity=initial_channel_capacity)
                    self.graph.add_edge(self.node_names[j], self.node_names[i], 
                                      balance=ba, fee=fee, capacity=initial_channel_capacity)
    
    def get_balance(self, node1: str, node2: str) -> int:
        return self.graph.get_edge_data(node1, node2, {}).get('balance', 0)
    
    def set_balance(self, node1: str, node2: str, amount: int):
        if self.graph.has_edge(node1, node2):
            self.graph[node1][node2]['balance'] = amount
        else:
            self.graph.add_edge(node1, node2, balance=amount, fee=random.randint(1, 15), 
                           capacity=1000)

    def find_path(self, source: str, target: str, amount: int) -> Tuple[Optional[List[str]], int]:
        try:
            temp_graph = nx.DiGraph()
            for u, v, data in self.graph.edges(data=True):
                if data['balance'] >= amount:
                    temp_graph.add_edge(u, v, weight=data['fee'])
            
            path = nx.shortest_path(temp_graph, source, target, weight='weight')
            total_fee = sum(self.graph[u][v]['fee'] for u, v in zip(path[:-1], path[1:]))
            return path, total_fee
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None, 0
    
    def send_payment(self, source: str, target: str, amount: int) -> Dict:
        path, total_fee = self.find_path(source, target, amount)
        result = {
            'source': source,
            'target': target,
            'amount': amount,
            'success': bool(path),
            'path': path,
            'fee': total_fee,
            'split_parts': []
        }
        
        if path:
            for u, v in zip(path[:-1], path[1:]):
                # Update forward channel
                self.graph[u][v]['balance'] -= amount
                
                # Ensure reverse channel exists before updating
                if not self.graph.has_edge(v, u):
                    # Create reverse channel if it doesn't exist
                    self.graph.add_edge(v, u, balance=0, fee=self.graph[u][v]['fee'], 
                                    capacity=self.graph[u][v]['capacity'])
                
                # Update reverse channel
                self.graph[v][u]['balance'] += amount
        
        return result
    
    def multi_part_payment(self, source: str, target: str, total_amount: int, max_parts=3) -> Dict:
        remaining = total_amount
        parts = []
        successful = True
        
        for _ in range(max_parts):
            part_amount = min(remaining, random.randint(50, total_amount//2))
            payment = self.send_payment(source, target, part_amount)
            if payment['success']:
                remaining -= part_amount
                parts.append(payment)
                if remaining <= 0:
                    break
            else:
                successful = False
                break
        
        total_fee = sum(p['fee'] for p in parts)
        return {
            'source': source,
            'target': target,
            'total_amount': total_amount,
            'success': successful,
            'parts': parts,
            'total_fee': total_fee
        }
    
    def circular_rebalance(self, node: str, amount: int) -> Dict:
        cycles = []
        for neighbor in self.graph.successors(node):
            if self.get_balance(node, neighbor) >= amount:
                path_back, _ = self.find_path(neighbor, node, amount)
                if path_back:
                    cycles.append([node] + path_back)
        
        if not cycles:
            return {'node': node, 'amount': amount, 'success': False, 'cycle': None}
        
        cycle = min(cycles, key=len)  # Choose shortest cycle
        for u, v in zip(cycle[:-1], cycle[1:]):
            # Update forward channel
            self.graph[u][v]['balance'] -= amount
            
            # Ensure reverse channel exists before updating
            if not self.graph.has_edge(v, u):
                # Create reverse channel if it doesn't exist
                self.graph.add_edge(v, u, balance=0, fee=self.graph[u][v]['fee'], 
                                capacity=self.graph[u][v]['capacity'])
            
            # Update reverse channel
            self.graph[v][u]['balance'] += amount
        
        return {'node': node, 'amount': amount, 'success': True, 'cycle': cycle}
    
    def generate_scenarios(self):
        # Select some key nodes that are well-connected
        central_nodes = sorted(self.graph.nodes(), 
                              key=lambda x: self.graph.out_degree(x), reverse=True)[:10]
        node_a, node_b, node_c, node_d, node_e, node_f, node_g = central_nodes[:7]
        
        # Scenario 1: Payment failures due to intermediate channel issues (3 examples)
        print("\n=== SCENARIO 1: PAYMENT FAILURES DUE TO INTERMEDIATE CHANNELS ===")
        self.scenario_1_intermediate_failures(node_a, node_b, node_c, node_d)
        
        # Scenario 2: Multi-part payments with higher costs (3 examples)
        print("\n=== SCENARIO 2: MULTI-PART PAYMENTS WITH HIGHER COSTS ===")
        self.scenario_2_multipart_payments(node_a, node_b, node_c)
        
        # Scenario 3: Ineffective circular rebalancing (3 examples)
        print("\n=== SCENARIO 3: INEFFECTIVE CIRCULAR REBALANCING ===")
        self.scenario_3_ineffective_rebalancing(node_a, node_b, node_c)
        
        # Scenario 4: Cascading circular rebalances (3 examples with increasing complexity)
        print("\n=== SCENARIO 4: CASCADING CIRCULAR REBALANCES ===")
        self.scenario_4_cascading_rebalances(node_a, node_b, node_c, node_d, node_e, node_f, node_g)
    
    def scenario_1_intermediate_failures(self, a, b, c, d):
        """Generate 3 examples of payment failures due to intermediate channel issues"""
        # Example 1: Simple 3-hop failure
        path, _ = self.find_path(a, c, 100)
        if len(path) >= 3:
            intermediate = path[1]
            self.set_balance(a, intermediate, 0)
            result = self.send_payment(a, c, 100)
            self.scenario_results['intermediate_failure'].append({
                'description': f"Basic 3-hop {a}->X->{c} with {a}->X drained",
                'result': result
            })
            print(f"Example 1: Drained {a}->{intermediate}, payment from {a} to {c} failed: {not result['success']}")
        
        # Example 2: Longer path failure
        long_path, _ = self.find_path(a, d, 100)
        if len(long_path) >= 4:
            intermediate = long_path[2]  # Third node in path
            prev_node = long_path[1]
            self.set_balance(prev_node, intermediate, 0)
            result = self.send_payment(a, d, 100)
            self.scenario_results['intermediate_failure'].append({
                'description': f"4-hop {a}->X->Y->{d} with Y->{d} drained",
                'result': result
            })
            print(f"Example 2: Drained {prev_node}->{intermediate}, payment from {a} to {d} failed: {not result['success']}")
        
        # Example 3: Multiple potential paths but all have bottlenecks
        self.set_balance(a, b, 200)
        self.set_balance(b, c, 0)  # Create bottleneck
        alt_path = self.find_alternative_path(a, c, 100)
        if alt_path and len(alt_path) >= 3:
            intermediate = alt_path[1]
            self.set_balance(a, intermediate, 0)  # Block alternative path
            result = self.send_payment(a, c, 100)
            self.scenario_results['intermediate_failure'].append({
                'description': f"Multiple paths from {a} to {c} but all blocked",
                'result': result
            })
            print(f"Example 3: All paths from {a} to {c} blocked, payment failed: {not result['success']}")
    
    def scenario_2_multipart_payments(self, a, b, c):
        """Generate 3 examples of multi-part payments with cost comparisons"""
        # Example 1: Simple 2-part payment
        large_amount = 500
        self.set_balance(a, b, 300)
        self.set_balance(b, c, 300)
        
        # First try single payment (should fail)
        single_result = self.send_payment(a, c, large_amount)
        if not single_result['success']:
            # Try multi-part
            multi_result = self.multi_part_payment(a, c, large_amount, 2)
            self.scenario_results['multipart_payment'].append({
                'description': f"Basic 2-part payment {a} to {c}",
                'single_result': single_result,
                'multi_result': multi_result
            })
            print(f"Example 1: Single payment fee would be ~{self.estimate_fee(a,c,large_amount)}, "
                  f"actual multi-part fee: {multi_result['total_fee']}")
        
        # Example 2: 3-part payment with different routes
        self.set_balance(a, b, 200)
        self.set_balance(b, c, 200)
        self.set_balance(a, c, 0)  # Force multi-path
        
        # Create alternative route
        d = random.choice([n for n in self.graph.nodes() if n not in [a,b,c]])
        self.set_balance(a, d, 200)
        self.set_balance(d, c, 200)
        
        single_result = self.send_payment(a, c, 600)
        if not single_result['success']:
            multi_result = self.multi_part_payment(a, c, 600, 3)
            self.scenario_results['multipart_payment'].append({
                'description': f"3-part payment {a} to {c} using multiple routes",
                'single_result': single_result,
                'multi_result': multi_result
            })
            print(f"Example 2: Complex 3-part payment, fee: {multi_result['total_fee']} "
                  f"vs estimated single: {self.estimate_fee(a,c,600)}")
        
        # Example 3: Large payment requiring many parts
        huge_amount = 1000
        # Make sure no single channel can handle it
        for u, v in self.graph.edges():
            if self.get_balance(u, v) > 800:
                self.set_balance(u, v, 300)
        
        single_result = self.send_payment(a, b, huge_amount)
        if not single_result['success']:
            multi_result = self.multi_part_payment(a, b, huge_amount, 5)
            self.scenario_results['multipart_payment'].append({
                'description': f"5-part large payment {a} to {b}",
                'single_result': single_result,
                'multi_result': multi_result
            })
            print(f"Example 3: Huge payment split into 5 parts, fee: {multi_result['total_fee']} "
                  f"(would be ~{self.estimate_fee(a,b,huge_amount)} if possible)")
    
    def scenario_3_ineffective_rebalancing(self, a, b, c):
        """Generate 3 examples where circular rebalancing is impossible"""
        # Example 1: No outbound liquidity at all
        for neighbor in self.graph.successors(a):
            self.set_balance(a, neighbor, 0)
        result = self.circular_rebalance(a, 100)
        self.scenario_results['ineffective_rebalance'].append({
            'description': f"{a} with zero outbound liquidity",
            'result': result
        })
        print(f"Example 1: {a} has no outbound, rebalance failed: {not result['success']}")
        
        # Example 2: Some outbound but not enough for cycle
        self.set_balance(a, b, 50)  # Some liquidity but not enough for cycle
        # Make sure b can't get back to a
        for neighbor in self.graph.successors(b):
            if neighbor != a:
                self.set_balance(b, neighbor, 0)
        result = self.circular_rebalance(a, 100)
        self.scenario_results['ineffective_rebalance'].append({
            'description': f"{a} has some outbound but no complete cycle",
            'result': result
        })
        print(f"Example 2: {a} has limited outbound, rebalance failed: {not result['success']}")
        
        # Example 3: Outbound exists but target has no inbound
        self.set_balance(a, b, 200)
        self.set_balance(b, c, 200)
        self.set_balance(c, a, 0)  # Break the cycle
        result = self.circular_rebalance(a, 100)
        self.scenario_results['ineffective_rebalance'].append({
            'description': f"Cycle {a}->{b}->{c}->{a} broken by {c}->{a}=0",
            'result': result
        })
        print(f"Example 3: Cycle broken by {c}->{a}=0, rebalance failed: {not result['success']}")
    
    def scenario_4_cascading_rebalances(self, a, b, c, d, e, f, g):
        """Generate 3 examples of cascading rebalances with increasing complexity"""
        # Example 1: Simple 2-step cascade
        # Setup initial balances
        self.set_balance(a, b, 300)
        self.set_balance(b, c, 300)
        self.set_balance(c, a, 300)
        
        # First rebalance drains b->c
        res1 = self.circular_rebalance(a, 200)
        # Now b needs rebalancing
        res2 = self.circular_rebalance(b, 150)
        
        self.scenario_results['cascading_rebalance'].append({
            'description': f"2-step cascade: {a} then {b}",
            'results': [res1, res2]
        })
        print(f"Example 1: 2-step cascade initiated by {a} then {b}")
        
        # Example 2: 3-step cascade
        # Setup more complex balances
        self.set_balance(a, b, 400)
        self.set_balance(b, c, 400)
        self.set_balance(c, d, 400)
        self.set_balance(d, a, 400)
        
        # First rebalance
        res1 = self.circular_rebalance(a, 300)
        # Second rebalance (b now needs it)
        res2 = self.circular_rebalance(b, 250)
        # Third rebalance (c now needs it)
        res3 = self.circular_rebalance(c, 200)
        
        self.scenario_results['cascading_rebalance'].append({
            'description': f"3-step cascade: {a} -> {b} -> {c}",
            'results': [res1, res2, res3]
        })
        print(f"Example 2: 3-step cascade through {a}, {b}, {c}")
        
        # Example 3: Complex cascade with multiple branches
        # Create a more complex network structure
        self.set_balance(a, b, 300)
        self.set_balance(b, c, 300)
        self.set_balance(c, d, 300)
        self.set_balance(d, e, 300)
        self.set_balance(e, a, 300)
        self.set_balance(a, f, 300)
        self.set_balance(f, g, 300)
        self.set_balance(g, a, 300)
        
        # Initial rebalance
        res1 = self.circular_rebalance(a, 250)
        # This affects both b and f
        res2 = self.circular_rebalance(b, 200)
        res3 = self.circular_rebalance(f, 200)
        # Which then affects c and g
        res4 = self.circular_rebalance(c, 150)
        res5 = self.circular_rebalance(g, 150)
        
        self.scenario_results['cascading_rebalance'].append({
            'description': f"5-step branching cascade from {a}",
            'results': [res1, res2, res3, res4, res5]
        })
        print(f"Example 3: Complex 5-step branching cascade initiated from {a}")
    
    def find_alternative_path(self, source, target, amount):
        """Find an alternative path when primary is blocked"""
        try:
            temp_graph = nx.DiGraph()
            for u, v, data in self.graph.edges(data=True):
                if data['balance'] >= amount and (u != source or v != target):
                    temp_graph.add_edge(u, v)
            
            return nx.shortest_path(temp_graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None
    
    def estimate_fee(self, source, target, amount):
        """Estimate what fee would be if there was enough liquidity"""
        path, fee = self.find_path(source, target, amount)
        return fee if path else float('inf')
    
    def visualize_scenario(self, scenario_name, example_idx):
        """Visualize a specific scenario example"""
        if scenario_name not in self.scenario_results or example_idx >= len(self.scenario_results[scenario_name]):
            print("Scenario or example not found")
            return
        
        example = self.scenario_results[scenario_name][example_idx]
        plt.figure(figsize=(14, 10))
        
        highlight_nodes = []
        highlight_edges = []
        
        if scenario_name == 'intermediate_failure':
            result = example['result']
            if result['path']:
                highlight_edges = list(zip(result['path'][:-1], result['path'][1:]))
            title = f"Scenario 1 Example {example_idx+1}: {example['description']}"
        
        elif scenario_name == 'multipart_payment':
            parts = example['multi_result']['parts']
            for part in parts:
                if part['path']:
                    highlight_edges.extend(list(zip(part['path'][:-1], part['path'][1:])))
            title = f"Scenario 2 Example {example_idx+1}: {example['description']}"
        
        elif scenario_name == 'ineffective_rebalance':
            result = example['result']
            highlight_nodes = [result['node']]
            if result['cycle']:
                highlight_edges = list(zip(result['cycle'][:-1], result['cycle'][1:]))
            title = f"Scenario 3 Example {example_idx+1}: {example['description']}"
        
        elif scenario_name == 'cascading_rebalance':
            for res in example['results']:
                if res['cycle']:
                    highlight_edges.extend(list(zip(res['cycle'][:-1], res['cycle'][1:])))
            title = f"Scenario 4 Example {example_idx+1}: {example['description']}"
        
        self._visualize_network(highlight_nodes=highlight_nodes, 
                            highlight_edges=highlight_edges,
                            title=title)

    def visualize_network(self, title="", highlight_nodes=None, highlight_edges=None):
        """Visualize the network with balances in both directions"""
        plt.figure(figsize=(20, 15))
        pos = nx.spring_layout(self.graph, k=0.5, iterations=50)
        
        # Draw nodes
        node_colors = ['red' if n in (highlight_nodes or []) else 'lightblue' 
                    for n in self.graph.nodes()]
        nx.draw_networkx_nodes(self.graph, pos, node_size=1000, node_color=node_colors, alpha=0.9)
        
        # Draw edges
        edge_colors = ['red' if (u,v) in (highlight_edges or []) else 'gray' 
                    for u,v in self.graph.edges()]
        nx.draw_networkx_edges(self.graph, pos, edge_color=edge_colors, width=2, 
                            arrowstyle='->', arrowsize=20, alpha=0.7)
        
        # Prepare edge labels for both directions
        edge_labels = {}
        for u, v, data in self.graph.edges(data=True):
            edge_labels[(u, v)] = f"{data['balance']} (fee:{data['fee']})"
        
        # Draw edge labels with adjusted positions
        nx.draw_networkx_edge_labels(
            self.graph, pos, 
            edge_labels=edge_labels,
            font_size=8,
            bbox=dict(alpha=0.7),
            label_pos=0.3  # Adjust label position along edge
        )
        
        # Draw node labels
        nx.draw_networkx_labels(self.graph, pos, font_size=12, font_weight='bold')
        
        plt.title(title, fontsize=16)
        plt.axis('off')
        plt.tight_layout()
        plt.show()

    def visualize_all_scenarios(self):
        """Visualize all generated scenarios"""
        # Visualize intermediate failures
        for i, example in enumerate(self.scenario_results['intermediate_failure']):
            path_edges = list(zip(example['result']['path'][:-1], example['result']['path'][1:])) \
                        if example['result']['path'] else []
            self.visualize_network(
                title=f"Scenario 1 Example {i+1}: {example['description']}",
                highlight_edges=path_edges
            )
        
        # Visualize multipart payments
        for i, example in enumerate(self.scenario_results['multipart_payment']):
            all_edges = []
            for part in example['multi_result']['parts']:
                if part['path']:
                    all_edges.extend(list(zip(part['path'][:-1], part['path'][1:])))
            self.visualize_network(
                title=f"Scenario 2 Example {i+1}: {example['description']}\n"
                    f"Total Fee: {example['multi_result']['total_fee']}",
                highlight_edges=all_edges
            )
        
        # Visualize ineffective rebalances
        for i, example in enumerate(self.scenario_results['ineffective_rebalance']):
            cycle_edges = list(zip(example['result']['cycle'][:-1], example['result']['cycle'][1:])) \
                        if example['result']['cycle'] else []
            self.visualize_network(
                title=f"Scenario 3 Example {i+1}: {example['description']}",
                highlight_nodes=[example['result']['node']],
                highlight_edges=cycle_edges
            )
        
        # Visualize cascading rebalances
        for i, example in enumerate(self.scenario_results['cascading_rebalance']):
            all_cycles = []
            for res in example['results']:
                if res['cycle']:
                    all_cycles.extend(list(zip(res['cycle'][:-1], res['cycle'][1:])))
            self.visualize_network(
                title=f"Scenario 4 Example {i+1}: {example['description']}",
                highlight_edges=all_cycles
            )

if __name__ == "__main__":
    # Create and run the simulation
    ln = ComprehensiveLightningNetwork(num_nodes=25, initial_channel_capacity=1000)
    ln.generate_scenarios()
    
    # Visualize specific examples
    print("\nVisualizing example scenarios...")
    ln.visualize_all_scenarios()
    
    # Visualize final network state
    ln.visualize_network("Final Network State")