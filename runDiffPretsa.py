import sys
import os
import argparse
from pretsa import Pretsa
import pandas as pd

sys.setrecursionlimit(3000)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Run PRETSA with differential privacy')
    parser.add_argument('current_log', help='Path to the current event log to be sanitized')
    parser.add_argument('k', type=int, help='k-anonymity parameter')
    parser.add_argument('t', type=float, help='t-closeness parameter')
    parser.add_argument('--prev_logs_dir', help='Directory containing previous event logs')
    parser.add_argument('--epsilon', type=float, default=0, 
                        help='Differential privacy parameter (smaller = more privacy)')
    parser.add_argument('--compare', action='store_true',
                        help='Also run original PRETSA and compare results')
    return parser.parse_args()

def count_patterns(log):
    """Count unique patterns in a log"""
    patterns = set()
    for case_id, group in log.groupby('Case ID'):
        if 'Event_Nr' in group.columns:
            sorted_group = group.sort_values('Event_Nr')
        else:
            sorted_group = group
        pattern = '-'.join(sorted_group['Activity'].tolist())
        patterns.add(pattern)
    return patterns

def main():
    args = parse_arguments()
    target_file_path = args.current_log.replace(".csv", 
        f"_t{args.t}_k{args.k}_eps{args.epsilon}_dp.csv")
    
    print("Loading current event log...")
    current_log = pd.read_csv(args.current_log, delimiter=";")
    
    # Load previous logs if directory is provided
    previous_logs = []
    if args.prev_logs_dir and os.path.isdir(args.prev_logs_dir):
        print(f"Loading previous event logs from {args.prev_logs_dir}...")
        for filename in os.listdir(args.prev_logs_dir):
            if filename.endswith('.csv'):
                log_path = os.path.join(args.prev_logs_dir, filename)
                try:
                    log = pd.read_csv(log_path, delimiter=";")
                    previous_logs.append(log)
                    print(f"  - Loaded {filename} ({len(log)} events)")
                except Exception as e:
                    print(f"  - Error loading {filename}: {e}")
    
    # Run original PRETSA if requested
    if args.compare:
        print(f"\nRunning original PRETSA (k={args.k}, t={args.t})")
        original_pretsa = Pretsa(current_log)
        original_cutout, original_distance = original_pretsa.runPretsa(args.k, args.t)
        original_log = original_pretsa.getPrivatisedEventLog()
        
        original_file_path = args.current_log.replace(".csv", f"_t{args.t}_k{args.k}_original.csv")
        original_log.to_csv(original_file_path, sep=";", index=False)
        print(f"Modified {len(original_cutout)} cases")
        print(f"Original PRETSA log has {len(original_log)} events and {len(original_log['Case ID'].unique())} cases")
    
    # Run DP-PRETSA
    print(f"\nRunning PRETSA with differential privacy (k={args.k}, t={args.t}, epsilon={args.epsilon})")
    print("Previous logs:", len(previous_logs))
    pretsa = Pretsa(current_log=current_log, previous_logs=previous_logs)
    pretsa.set_privacy_parameters(epsilon=args.epsilon)
    
    cut_out_cases, log_distance = pretsa.runPretsa(args.k, args.t, differentialPrivacy=True)
    dp_log = pretsa.getPrivatisedEventLog()
    
    dp_log.to_csv(target_file_path, sep=";", index=False)
    print(f"Modified {len(cut_out_cases)} cases")
    print(f"DP-PRETSA log has {len(dp_log)} events and {len(dp_log['Case ID'].unique())} cases")
    
    # Simple comparison if original was run
    if args.compare:
        orig_patterns = count_patterns(original_log)
        dp_patterns = count_patterns(dp_log)
        
        print("\n--- COMPARISON: Original vs DP-PRETSA ---")
        print(f"Events:          {len(original_log)} vs {len(dp_log)} (diff: {len(dp_log) - len(original_log)})")
        print(f"Cases:           {len(original_log['Case ID'].unique())} vs {len(dp_log['Case ID'].unique())} (diff: {len(dp_log['Case ID'].unique()) - len(original_log['Case ID'].unique())})")
        print(f"Unique patterns: {len(orig_patterns)} vs {len(dp_patterns)} (diff: {len(dp_patterns) - len(orig_patterns)})")
        print(f"Common patterns: {len(orig_patterns & dp_patterns)}")
        print(f"Only in original: {len(orig_patterns - dp_patterns)}")
        print(f"Only in DP log:   {len(dp_patterns - orig_patterns)}")

if __name__ == "__main__":
    main()