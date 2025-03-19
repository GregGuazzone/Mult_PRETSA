import threading
import numpy as np
import pandas as pd
from cryptography.fernet import Fernet
import pickle
import socket
import time
from pretsa import Pretsa

class MPCCoordinator:
    """MPC coordinator for PRETSA analysis"""
    def __init__(self, port=5001):
        self.port = port
        self.participants = {}
        self.logs = {}
        self.k = 3
        self.t = 0.2
        self.epsilon = 1.0
        self.server_thread = None
        self.running = True
        
    def set_privacy_parameters(self, k, t, epsilon):
        """Sets privacy parameters"""
        self.k = k
        self.t = t
        self.epsilon = epsilon
        print(f"Privacy parameters set: k={k}, t={t}, epsilon={epsilon}")
        
    def start_server(self):
        """Starts the server in a separate thread to listen for participant connections"""
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True  # Allow the thread to exit when main program exits
        self.server_thread.start()
        print(f"MPC Coordinator started on port {self.port}")
        
    def _run_server(self):
        """Runs the server to accept participant connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(5)
        
        while self.running:
            try:
                self.server_socket.settimeout(1.0)  # Add timeout to allow checking running flag
                try:
                    client_socket, address = self.server_socket.accept()
                    self._handle_participant(client_socket, address)
                except socket.timeout:
                    continue  # No connection received, check running flag and continue
            except Exception as e:
                print(f"Server error: {e}")
                break
                
        print("Server stopped")
        
    def stop_server(self):
        """Stops the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.server_thread:
            self.server_thread.join(2.0)  # Wait for server thread to finish
    
    def _handle_participant(self, client_socket, address):
        """Handles a participant connection"""
        try: # to receive participant data
            data = self._receive_message(client_socket)
            participant_id = data['id']
            encrypted_log = data['log']
            key = data['key']
            
            self.participants[participant_id] = {       # Store participant info
                'socket': client_socket,
                'address': address,
                'key': key
            }
            
            # Store encrypted log
            self.logs[participant_id] = encrypted_log
            print(f"Received log from participant {participant_id}")
            print(f"Total participants connected: {len(self.participants)}")

        except Exception as e:
            print(f"Error handling participant: {e}")
            try:
                self._send_message(client_socket, {'error': str(e)})        # Send error back to client
            except:
                pass
            client_socket.close()
    
    def execute_secure_computation(self):
        """Triggers the secure computation"""
        if len(self.participants) < 2:
            print(f"Not enough participants connected")
            return False
            
        try:
            print(f"Starting computation with {len(self.participants)} participants...")
            self._run_analysis()
            return True
        except Exception as e:
            print(f"Error during computation: {e}")
            # Send error message back to participants
            for pid, info in self.participants.items():
                try:
                    self._send_message(info['socket'], {'error': str(e)})
                except:
                    pass
            return False
    
    def _receive_message(self, socket):
        """Receives a message from a participant"""
        message_length = int.from_bytes(socket.recv(4), byteorder='big')
        
        # Receive the message
        data = b''
        bytes_received = 0
        while bytes_received < message_length:
            chunk = socket.recv(min(4096, message_length - bytes_received))
            data += chunk
            bytes_received += len(chunk)
        return pickle.loads(data)
    
    def _send_message(self, socket, message):
        """Sends a message to a participant"""
        serialized = pickle.dumps(message)
        length = len(serialized).to_bytes(4, byteorder='big')
        socket.sendall(length + serialized)
    
    def _run_analysis(self):
        """Runs secure PRETSA analysis on the combined data"""
        # 1. Decrypt and combine logs
        combined_log = self._combine_logs()
        
        # 2. Run PRETSA on the combined data
        pretsa = Pretsa(combined_log)
        cutout_cases, log_distance = pretsa.runPretsa(self.k, self.t)
        privatized_log = pretsa.getPrivatisedEventLog()
        
        # 3. Split results by participant ID
        for participant_id, info in self.participants.items():
            # Filter log for this participant
            participant_log = privatized_log[privatized_log['Participant_ID'] == participant_id]
            
            if 'Participant_ID' in participant_log.columns:     # Remove participant ID column
                participant_log = participant_log.drop('Participant_ID', axis=1)
            
            cipher = Fernet(info['key'])                        # Encrypt the result with the participant's key
            encrypted_result = cipher.encrypt(pickle.dumps(participant_log))
            
            self._send_message(info['socket'], {'result': encrypted_result})    # Send result to participant
            print(f"Sent privatized log to participant {participant_id}")
    
    def _combine_logs(self):
        """Combines the logs"""
        combined_df = pd.DataFrame()
        for participant_id, log in self.logs.items():
            cipher = Fernet(self.participants[participant_id]['key'])     # Decrypt the log with the participant's key
            log_data = pickle.loads(cipher.decrypt(log))
            
            log_df = pd.DataFrame(log_data)             
            log_df['Participant_ID'] = participant_id                     # Add a Participant_ID column to track which rows belong to which participant

            combined_df = pd.concat([combined_df, log_df])                # Combine the logs
        return combined_df


class MPCParticipant:
    """MPC participant for PRETSA analysis"""
    
    def __init__(self, participant_id, event_log, coordinator_host='localhost', coordinator_port=5001):
        self.id = participant_id
        self.event_log = event_log
        self.coordinator_host = coordinator_host
        self.coordinator_port = coordinator_port
        self.key = Fernet.generate_key()  # Generate a unique encryption key
    
    def connect_to_coordinator(self):
        """Connects to the MPC coordinator and submit log"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Connect to coordinator
            self.socket.connect((self.coordinator_host, self.coordinator_port))
            
            cipher = Fernet(self.key)
            encrypted_log = cipher.encrypt(pickle.dumps(self.event_log))        # Encrypt our event log
            
            self._send_message({        # Send log to the coordinator
                'id': self.id,
                'log': encrypted_log,
                'key': self.key
            })
            
            print(f"Sent encrypted log to coordinator")
            
            try:    # to wait for the result
                result = self._receive_message()
                
                if 'error' in result:
                    print(f"Coordinator returned error: {result['error']}")
                    return None
                    
                privatized_log = pickle.loads(cipher.decrypt(result['result']))     # Decrypt the result
                
                output_path = f"privatized_{self.id}.csv"               
                privatized_log.to_csv(output_path, sep=";", index=False)            # Save the privatized log to a file 
                print(f"Received and saved privatized log")
                
                return privatized_log
            except Exception as e:
                print(f"Error receiving result: {e}")
                return None
                
        except Exception as e:
            print(f"Error connecting to coordinator: {e}")
            return None
    
    def _send_message(self, message):
        """Sends a message to the coordinator"""
        serialized = pickle.dumps(message)
        length = len(serialized).to_bytes(4, byteorder='big')
        self.socket.sendall(length + serialized)
    
    def _receive_message(self):
        """Receives a message from the coordinator with timeout"""
        try:
            # Set socket timeout to prevent hanging
            self.socket.settimeout(300.0)  # 300 second timeout
            
            # Get message length
            length_bytes = self.socket.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                raise Exception("Connection closed or invalid length received")
                
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive the message
            data = b''
            bytes_received = 0
            while bytes_received < message_length:
                chunk_size = min(4096, message_length - bytes_received)
                chunk = self.socket.recv(chunk_size)
                if not chunk:
                    raise Exception(f"Connection closed after receiving {bytes_received} of {message_length} bytes")
                data += chunk
                bytes_received += len(chunk)
            
            # Reset timeout
            self.socket.settimeout(None)
            return pickle.loads(data)
        except socket.timeout:
            raise Exception("Connection timed out while receiving data")