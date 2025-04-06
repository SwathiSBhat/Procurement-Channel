import networkx as nx
import random
from typing import Dict, Tuple, List, Optional
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from collections import defaultdict

class AdvancedLightningNetwork:
    def __init__(self, num_nodes=20, initial_channel_capacity=500, channel_density=0.25):
        self.num_nodes = num_nodes
        self.graph = nx.DiGraph()
        self.node_names = [f'Node_{i}' for i in range(num_nodes)]
        self.graph.add_nodes_from(self.node_names)
        self.payment_history = []
        self.rebalance_history = []
        
        # Create channels with some density
        for i in range(num_nodes):
            for j in range(i+1, num_nodes):
                if random.random() < channel_density:
                    # Split initial capacity randomly between directions
                    ab = random.randint(100, initial_channel_capacity-100)
                    ba = initial_channel_capacity - ab
                    self.graph.add_edge(self.node_names[i], self.node_names[j], balance=ab, fee=random.randint(1, 10))
                    self.graph.add_edge(self.node_names[j], self.node_names[i], balance=ba, fee=random.randint(1, 10))
    
    def get_balance(self, node1: str, node2: str) -> int:
        """Get balance from node1 to node2"""
        if self.graph.has_edge(node1, node2):
            return self.graph[node1][node2]['balance']
        return 0
    
    def set_balance(self, node1: str, node2: str, amount: int):
        """Set balance from node1 to node2"""
        if self.graph.has_edge(node1, node2):
            self.graph[node1][node2]['balance'] = amount
        else:
            self.graph.add_edge(node1, node2, balance=amount, fee=random.randint(1, 10))
    
    def find_path(self, source: str, target: str, amount: int) -> Optional[List[str]]:
        """Find a path with sufficient liquidity and return path with total fee"""
        try:
            # Create a temporary graph where edges with insufficient balance are removed
            temp_graph = nx.DiGraph()
            for u, v, data in self.graph.edges(data=True):
                if data['balance'] >= amount:
                    temp_graph.add_edge(u, v, weight=data['fee'])
            
            path = nx.shortest_path(temp_graph, source, target, weight='weight')
            total_fee = sum(self.graph[u][v]['fee'] for u, v in zip(path[:-1], path[1:]))
            return path, total_fee
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None, 0
    
    def send_payment(self, source: str, target: str, amount: int) -> Tuple[bool, List[str], int]:
        """Attempt to send a payment through the network"""
        path, total_fee = self.find_path(source, target, amount)
        if not path:
            self.payment_history.append({
                'source': source,
                'target': target,
                'amount': amount,
                'success': False,
                'path': None,
                'fee': 0
            })
            return False, None, 0
        
        # Update balances along the path
        for i in range(len(path)-1):
            u, v = path[i], path[i+1]
            current_balance = self.get_balance(u, v)
            self.set_balance(u, v, current_balance - amount)
            
            # Increase reverse balance (HTLC)
            current_reverse = self.get_balance(v, u)
            self.set_balance(v, u, current_reverse + amount)
        
        self.payment_history.append({
            'source': source,
            'target': target,
            'amount': amount,
            'success': True,
            'path': path,
            'fee': total_fee
        })
        return True, path, total_fee
    
    def circular_rebalance(self, node: str, amount: int) -> Tuple[bool, List[str]]:
        """Attempt a circular rebalance to increase outbound liquidity from node"""
        # Find all cycles that include the node and have sufficient liquidity
        cycles = []
        for neighbor in self.graph.successors(node):
            if self.get_balance(node, neighbor) >= amount:
                # Try to find a path back to node from neighbor
                path_back, _ = self.find_path(neighbor, node, amount)
                if path_back:
                    full_cycle = [node] + path_back
                    cycles.append(full_cycle)
        
        if not cycles:
            self.rebalance_history.append({
                'node': node,
                'amount': amount,
                'success': False,
                'cycle': None
            })
            return False, None
        
        # Choose the shortest cycle
        cycle = min(cycles, key=len)
        
        # Execute the rebalance
        for i in range(len(cycle)-1):
            u, v = cycle[i], cycle[i+1]
            current_balance = self.get_balance(u, v)
            self.set_balance(u, v, current_balance - amount)
            
            # Increase reverse balance
            current_reverse = self.get_balance(v, u)
            self.set_balance(v, u, current_reverse + amount)
        
        self.rebalance_history.append({
            'node': node,
            'amount': amount,
            'success': True,
            'cycle': cycle
        })
        return True, cycle
    
    def visualize(self, title="Lightning Network", highlight_nodes=None, highlight_edges=None):
        """Visualize the network with channel balances in both directions"""
        plt.figure(figsize=(16, 12))
        pos = nx.spring_layout(self.graph, k=0.5, iterations=50)
        
        # Draw nodes
        node_colors = []
        for node in self.graph.nodes():
            if highlight_nodes and node in highlight_nodes:
                node_colors.append('red')
            else:
                node_colors.append('lightblue')
        nx.draw_networkx_nodes(self.graph, pos, node_size=800, node_color=node_colors, alpha=0.9)
        
        # Draw edges with balance information
        edge_colors = []
        edge_widths = []
        for u, v in self.graph.edges():
            if highlight_edges and (u, v) in highlight_edges:
                edge_colors.append('red')
                edge_widths.append(3.0)
            else:
                edge_colors.append('gray')
                edge_widths.append(1.0)
        
        nx.draw_networkx_edges(self.graph, pos, width=edge_widths, edge_color=edge_colors, 
                              arrowstyle='->', arrowsize=15, alpha=0.7)
        
        # Draw edge labels with both directions
        edge_labels = {}
        for u, v, data in self.graph.edges(data=True):
            edge_labels[(u, v)] = f"{data['balance']}"
        
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels, font_size=8)
        
        # Draw node labels
        nx.draw_networkx_labels(self.graph, pos, font_size=10, font_weight='bold')
        
        plt.title(title, fontsize=14)
        plt.axis('off')
        plt.tight_layout()
        plt.show()
    
    def print_node_balances(self, node: str):
        """Print all channel balances for a specific node"""
        print(f"\nChannel balances for {node}:")
        for neighbor in self.graph.neighbors(node):
            out_balance = self.get_balance(node, neighbor)
            in_balance = self.get_balance(neighbor, node)
            fee = self.graph[node][neighbor]['fee']
            print(f"  {node} -> {neighbor}: {out_balance} (fee: {fee})")
            print(f"  {neighbor} -> {node}: {in_balance} (fee: {fee})")
    
    def generate_liquidity_crisis(self):
        """Generate specific scenarios demonstrating liquidity problems"""
        print("\n=== Generating Liquidity Crisis Scenarios ===")
        
        # Select some key nodes
        node_a = 'Node_0'
        node_b = 'Node_5'
        node_c = 'Node_10'
        node_d = 'Node_15'
        node_e = 'Node_3'
        
        # Scenario 1: Payment failure due to intermediate channel lacking liquidity
        print("\n--- Scenario 1: Payment Failure Due to Intermediate Channel ---")
        # First ensure a path exists
        path, _ = self.find_path(node_a, node_d, 100)
        if path:
            # Find an intermediate channel and drain it
            intermediate = path[1]  # Second node in path
            self.set_balance(node_a, intermediate, 0)
            print(f"Drained {node_a}->{intermediate} to force payment failure")
            
            # Attempt payment
            success, _, _ = self.send_payment(node_a, node_d, 100)
            if not success:
                print("Payment failed as expected due to intermediate channel lacking liquidity")
        
        # Scenario 2: Multi-part payments with higher routing costs
        print("\n--- Scenario 2: Multi-part Payments with Higher Costs ---")
        large_amount = 300
        print(f"Attempting to send {large_amount} from {node_b} to {node_e}")
        
        # Try full amount first (should fail)
        success, _, _ = self.send_payment(node_b, node_e, large_amount)
        if not success:
            print("Full payment failed, attempting multi-part...")
            # Try splitting into parts
            part1 = 100
            part2 = 100
            part3 = 100
            success1, path1, fee1 = self.send_payment(node_b, node_e, part1)
            success2, path2, fee2 = self.send_payment(node_b, node_e, part2)
            success3, path3, fee3 = self.send_payment(node_b, node_e, part3)
            
            if success1 and success2 and success3:
                total_fee = fee1 + fee2 + fee3
                print(f"Multi-part successful with total fees: {total_fee}")
                # Compare with what fee would be if there was enough liquidity
                _, full_fee = self.find_path(node_b, node_e, large_amount)
                print(f"Estimated fee for full payment if possible: {full_fee}")
        
        # Scenario 3: Ineffective circular rebalancing due to low outbound liquidity
        print("\n--- Scenario 3: Failed Circular Rebalance Due to Low Outbound ---")
        # Drain all outbound from node_c
        for neighbor in self.graph.successors(node_c):
            self.set_balance(node_c, neighbor, 0)
        print(f"Drained all outbound liquidity from {node_c}")
        
        # Attempt rebalance
        success, _ = self.circular_rebalance(node_c, 100)
        if not success:
            print(f"Rebalance failed as expected - no outbound liquidity from {node_c}")
        
        # Scenario 4: Cascading circular rebalances
        print("\n--- Scenario 4: Cascading Circular Rebalances ---")
        # First create a situation where rebalance in one place causes issues elsewhere
        # Select a cycle: node_a -> node_b -> node_c -> node_a
        # Set initial balances to allow rebalance
        self.set_balance(node_a, node_b, 200)
        self.set_balance(node_b, node_c, 200)
        self.set_balance(node_c, node_a, 200)
        
        print("Initial balances for cascade scenario:")
        self.print_node_balances(node_a)
        self.print_node_balances(node_b)
        self.print_node_balances(node_c)
        
        # First rebalance from node_a
        print(f"\nFirst rebalance from {node_a}")
        success, cycle1 = self.circular_rebalance(node_a, 150)
        if success:
            print(f"Rebalance successful along {cycle1}")
            print("New balances:")
            self.print_node_balances(node_a)
            self.print_node_balances(node_b)
            self.print_node_balances(node_c)
            
            # Now node_b may need rebalancing
            print(f"\n{node_b} now needs rebalancing due to depleted channel to {node_c}")
            success, cycle2 = self.circular_rebalance(node_b, 100)
            if success:
                print(f"Second rebalance successful along {cycle2}")
                print("Final balances:")
                self.print_node_balances(node_a)
                self.print_node_balances(node_b)
                self.print_node_balances(node_c)
        
        # Visualize the final state with highlighted problem areas
        self.visualize("Network After Liquidity Crisis Scenarios", 
                      highlight_nodes=[node_a, node_b, node_c, node_d, node_e])

if __name__ == "__main__":
    # Create a larger network
    ln = AdvancedLightningNetwork(num_nodes=20, initial_channel_capacity=500, channel_density=0.25)
    print("Advanced Lightning Network created with 20 nodes")
    
    # Visualize the initial network
    ln.visualize("Initial Lightning Network")
    
    # Generate specific liquidity crisis scenarios
    ln.generate_liquidity_crisis()
    
    # Print some statistics
    print("\n=== Simulation Statistics ===")
    print(f"Total payments attempted: {len(ln.payment_history)}")
    print(f"Successful payments: {sum(1 for p in ln.payment_history if p['success'])}")
    print(f"Total rebalances attempted: {len(ln.rebalance_history)}")
    print(f"Successful rebalances: {sum(1 for r in ln.rebalance_history if r['success'])}")