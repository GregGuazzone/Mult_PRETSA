import os
import time
import argparse
from mpc_pretsa import MPCCoordinator

def main():
    parser = argparse.ArgumentParser(description="Run MPC Coordinator with privacy parameters.")
    parser.add_argument("--k", type=int, default=3, help="k-anonymity parameter (default: 3)")
    parser.add_argument("--t", type=float, default=0.2, help="t-closeness parameter (default: 0.2)")
    args = parser.parse_args()

    # Create and start the MPC coordinator
    coordinator = MPCCoordinator(port=5001)
    coordinator.start_server()
    coordinator.set_privacy_parameters(args.k, args.t, 0)
    
    # Wait for participants to connect
    print("Waiting for participants to connect...")
    time.sleep(10)
    
    # Set privacy parameters
    
    # Wait for user input to start computation
    while True:
        cmd = input("Press 'c' to start computation or 'q' to quit: ")
        if cmd.lower() == 'c':
            # Execute secure computation
            coordinator.execute_secure_computation()
        elif cmd.lower() == 'q':
            break
        else:
            print("Invalid input. Please press 'c' to start computation or 'q' to quit.")
        time.sleep(1)

if __name__ == "__main__":
    main()