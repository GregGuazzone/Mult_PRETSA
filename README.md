## Features added:
- Differential Privacy:
- Multi-Party Computation:

### Differential Privacy:
A type of attack that was not accounted for was the temporal aggregation of event logs by an attacker, who can then use background information like employee presence information to infer certain traces to particular employees. The authors failed to account for the temporal dimension of the event logs, which can be used to infer certain traces to particular employees.
Suppose there is a very simplified example where there is a sequence A, B, and C in time t and attacker has background information that employees X, Y, and Z were employed in this time period. Now suppose that is only sequence A and B in time t+1 and the attacker knows that employee Z was no longer employed. The attacker can infer that employee Z was responsible for event C. The defense also has a lower privacy guarantee for employees X and Y as the attacker can infer that they were not responsible for event C.
Differential privacy protects against temporal correlation attacks by introducing uncertainty in the presence or absence of specific activity sequences. When an attacker observes changes between temporal releases (e.g., an activity sequence present in time t but absent in t+1), they cannot confidently attribute this to actual employee changes.

* Modified PRETSA:
  1. If `previous_logs` are provided, `__extract_previous_traces(self)` is called to extract the traces from the previous logs.
  2. After the original PRETSA is ran, `__apply_differential_privacy(self)` is called to add noise to the traces.

The modified algorithm now:
- Takes in a event logs that were previously released
- The differential privacy implementation utilizes the Laplace mechanism to add controlled noise to sequence counts, protecting against temporal correlation attacks. Trace matching between current and previous logs is performed by extracting activity sequences and applying noise `(np.random.laplace(0, 1/epsilon))`

> Note: I split up the provided dataframe by year to simulate temporal releases.

- To run:
  - `python runDiffPretsa.py <current_log_path> [k] [t] --prev_logs_dir <previous_logs_dir> --epsilon [epsilon]`
  - example: `python runDiffPretsa.py yearly_logs/bpic2013/bpic2013_dataset_2012.csv 4 0.5 --prev_logs_dir yearly_logs/bpic2013/released --epsilon 0.1`

- Add `--compare` to run a comparison between the original and the differentially private
  - example: `python runDiffPretsa.py yearly_logs/bpic2013/bpic2013_dataset_2012.csv 4 0.5 --prev_logs_dir yearly_logs/bpic2013/released --epsilon 0.1 --compare`

### Multi-Party Computation:
Suppose different parts of a business hold different parts of the whole business' event log. Some employees might work in multiple departments and affect different department's event logs, so privacy guarantee must be cross-departmental and be ensured for the whole business. This feature allows a central coordinator to compute the overrall pretsa event log and then splits it back up to the different departments.
The MPC implementation uses the Fernet symmetric encryption scheme to protect data in transit between participants and coordinator. Each participant generates a unique key `(Fernet.generate_key())`, encrypts their log `(cipher.encrypt(pickle.dumps(self.event_log)))`, and only receives their portion of the sanitized result.

- To run:
  - As coordinator: `python run_mpc_coordinator.py`, wait for participants and input `c` to start the computation (when restarting, the port needs to clear ~10 seconds)
  - As a participant: `python run_mpc_participant.py <participant_id> <log_file>`
