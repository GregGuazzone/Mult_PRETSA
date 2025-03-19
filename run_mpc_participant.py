import sys
import pandas as pd
import time
from mpc_pretsa import MPCParticipant

def main():
    if len(sys.argv) < 3:
        print("Usage: python run_mpc_participant.py <participant_id> <log_file> [coordinator_host]")
        sys.exit(1)
    
    participant_id = sys.argv[1]
    log_file = sys.argv[2]
    coordinator_host = sys.argv[3] if len(sys.argv) > 3 else 'localhost'
    
    # Load event log
    print(f"Loading event log from {log_file}...")
    event_log = pd.read_csv(log_file, delimiter=';')
    
    # Create and connect participant
    participant = MPCParticipant(participant_id, event_log, coordinator_host)
    connected = participant.connect_to_coordinator()
    
    if connected is None:
        print("Failed to connect to coordinator")
        sys.exit(1)
    
    print(f"Participant {participant_id} connected and waiting for instructions...")
    
    # Keep participant running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping participant...")

if __name__ == "__main__":
    main()