import networkx as nx
import random
from typing import Dict, Tuple, List
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors

class LightningNetwork:
    def __init__(self, num_nodes=15, initial_channel_capacity=200, channel_density=0.3):
        self.num_nodes = num_nodes
        self.graph = nx.DiGraph()
        self.node_names = [f'Node_{i}' for i in range(num_nodes)]
        self.graph.add_nodes_from(self.node_names)
        
        # Create channels with some density
        for i in range(num_nodes):
            for j in range(i+1, num_nodes):
                if random.random() < channel_density:
                    # Split initial capacity randomly between directions
                    ab = random.randint(50, initial_channel_capacity-50)
                    ba = initial_channel_capacity - ab
                    self.graph.add_edge(self.node_names[i], self.node_names[j], balance=ab)
                    self.graph.add_edge(self.node_names[j], self.node_names[i], balance=ba)
    
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
            self.graph.add_edge(node1, node2, balance=amount)
    
    def find_path(self, source: str, target: str, amount: int) -> List[str]:
        """Find a path with sufficient liquidity"""
        try:
            # We need to find a path where each channel has at least 'amount' balance
            # So we'll create a temporary graph where edges with insufficient balance are removed
            temp_graph = self.graph.copy()
            for u, v, data in list(temp_graph.edges(data=True)):
                if data['balance'] < amount:
                    temp_graph.remove_edge(u, v)
            
            return nx.shortest_path(temp_graph, source, target)
        except nx.NetworkXNoPath:
            return None
    
    def send_payment(self, source: str, target: str, amount: int) -> bool:
        """Attempt to send a payment through the network"""
        path = self.find_path(source, target, amount)
        if not path:
            print(f"No path found from {source} to {target} for amount {amount}")
            return False
        
        print(f"Payment path: {' -> '.join(path)}")
        
        # Update balances along the path
        for i in range(len(path)-1):
            u, v = path[i], path[i+1]
            current_balance = self.get_balance(u, v)
            self.set_balance(u, v, current_balance - amount)
            
            # Increase reverse balance (HTLC)
            current_reverse = self.get_balance(v, u)
            self.set_balance(v, u, current_reverse + amount)
        
        print(f"Successfully sent {amount} from {source} to {target}")
        return True
    
    def circular_rebalance(self, node: str, amount: int) -> bool:
        """Attempt a circular rebalance to increase outbound liquidity from node"""
        # Find a cycle that includes the node
        for neighbor in self.graph.successors(node):
            if self.get_balance(node, neighbor) >= amount:
                # Try to find a path back to node from neighbor
                path_back = self.find_path(neighbor, node, amount)
                if path_back:
                    full_cycle = [node] + path_back
                    print(f"Circular rebalance path: {' -> '.join(full_cycle)}")
                    
                    # Execute the rebalance
                    for i in range(len(full_cycle)-1):
                        u, v = full_cycle[i], full_cycle[i+1]
                        current_balance = self.get_balance(u, v)
                        self.set_balance(u, v, current_balance - amount)
                        
                        # Increase reverse balance
                        current_reverse = self.get_balance(v, u)
                        self.set_balance(v, u, current_reverse + amount)
                    
                    print(f"Successfully rebalanced {amount} along cycle")
                    return True
        
        print(f"No suitable cycle found for rebalancing from {node}")
        return False
    
    def visualize(self, title="Lightning Network"):
        """Visualize the network with channel balances"""
        plt.figure(figsize=(12, 10))
        pos = nx.spring_layout(self.graph)
        
        # Draw nodes
        nx.draw_networkx_nodes(self.graph, pos, node_size=700, node_color='lightblue')
        
        # Draw edges with balance information
        edge_labels = {}
        for u, v, data in self.graph.edges(data=True):
            edge_labels[(u, v)] = data['balance']
        
        nx.draw_networkx_edges(self.graph, pos, width=1.5, arrowstyle='->', arrowsize=15)
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels, font_size=8)
        
        # Draw node labels
        nx.draw_networkx_labels(self.graph, pos, font_size=10, font_weight='bold')
        
        plt.title(title)
        plt.axis('off')
        plt.tight_layout()
        plt.show()
    
    def print_node_balances(self, node: str):
        """Print all channel balances for a specific node"""
        print(f"\nChannel balances for {node}:")
        for neighbor in self.graph.neighbors(node):
            out_balance = self.get_balance(node, neighbor)
            in_balance = self.get_balance(neighbor, node)
            print(f"  {node} -> {neighbor}: {out_balance}")
            print(f"  {neighbor} -> {node}: {in_balance}")

def simulate_complex_scenario():
    # Create a network with 15 nodes
    ln = LightningNetwork(num_nodes=15, initial_channel_capacity=300, channel_density=0.25)
    print("Initial Lightning Network created with 15 nodes")
    
    # Visualize the initial network
    ln.visualize("Initial Lightning Network")
    
    # Select some key nodes for our scenario
    node_a = 'Node_0'
    node_b = 'Node_5'
    node_c = 'Node_10'
    
    # Print initial balances for these nodes
    ln.print_node_balances(node_a)
    ln.print_node_balances(node_b)
    ln.print_node_balances(node_c)
    
    # Scenario 1: Initial payment that drains some channels
    print("\n=== Scenario 1: Initial payment ===")
    payment1_success = ln.send_payment(node_a, node_c, 80)
    
    # Print balances after first payment
    ln.print_node_balances(node_a)
    ln.print_node_balances(node_c)
    
    # Scenario 2: Attempt another payment that fails due to insufficient liquidity
    print("\n=== Scenario 2: Failed payment ===")
    payment2_success = ln.send_payment(node_a, node_c, 150)
    
    # Scenario 3: Attempt circular rebalance to create outbound liquidity
    print("\n=== Scenario 3: Circular rebalance ===")
    rebalance_success = ln.circular_rebalance(node_a, 100)
    
    # Print balances after rebalance
    ln.print_node_balances(node_a)
    
    # Scenario 4: Check if the rebalance caused issues elsewhere
    print("\n=== Scenario 4: Check affected nodes ===")
    # Find which nodes were part of the rebalance cycle
    # In a real simulation, we would track this, but here we'll just check some nodes
    ln.print_node_balances(node_b)
    
    # Scenario 5: New payment that now requires another rebalance
    print("\n=== Scenario 5: New payment requiring another rebalance ===")
    payment3_success = ln.send_payment(node_b, node_a, 120)
    if not payment3_success:
        print("Attempting rebalance from another node")
        ln.circular_rebalance(node_b, 100)
        # Try payment again
        payment3_success = ln.send_payment(node_b, node_a, 120)
    
    # Scenario 6: Multi-part payments
    print("\n=== Scenario 6: Multi-part payment ===")
    large_amount = 200
    print(f"Attempting to send {large_amount} from {node_c} to {node_a}")
    
    # Try full amount first
    if not ln.send_payment(node_c, node_a, large_amount):
        print("Full amount failed, trying split into two parts")
        # Try splitting into two parts
        part1 = large_amount // 2
        part2 = large_amount - part1
        success1 = ln.send_payment(node_c, node_a, part1)
        success2 = ln.send_payment(node_c, node_a, part2)
        if success1 and success2:
            print("Successfully completed multi-part payment")
    
    # Final visualization
    ln.visualize("Lightning Network After Simulations")

if __name__ == "__main__":
    simulate_complex_scenario()