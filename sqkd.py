from qiskit import *
import math
import numpy as np
import hashlib
import hmac
import time
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Padding
from qiskit.tools.visualization import circuit_drawer

simulator = Aer.get_backend('qasm_simulator')

# size of INFO BITS for sqkd
n = 2

# delta parameter for sqkd
delta = 0

# (Z-)error threshold for CTRL for sqkd
p_ctrl = 0.5

# (Z-)error threshold for SIFT for sqkd
p_test = 0.5

def encodeSQKD(basis, message_bit, circuit, idx):
	'''
	basis(int): defines what basis is the message encode. 0 (Computational) and 1 (Hadamard)
	message_bit (int):
    0 is encoded as |0> or |+>
    1 is encoded as |1> or |->
    circuit(QuantumCircuit): the circuit used for communication
    idx(int): index of the message_bit
	'''
	if message_bit == 1:
		circuit.x(idx)
	if basis == 1:
		circuit.h(idx)
	return circuit

def sqkd():

    # number of bits to be set to device
    N = math.ceil(8*n*(1+delta))

    # generate a message for sqkd (binary array)
    message = np.random.randint(2, size=N)
    # print(f'{message=}')

    # generate basis for encoding qubits by control center (quantum)
    cc_basis = np.random.randint(2, size=N)
    # print(f'{cc_basis=}')

    # circuit for sending data to device
    circuit = QuantumCircuit(N, N)

    for (idx, (basis, message_bit)) in enumerate(zip(cc_basis, message)):
        circuit = encodeSQKD(basis, message_bit, circuit, idx)

    circuit.barrier()

    # device basis for SIFT or CTRL
    device_decisions = np.random.randint(2, size=N)
    # print(f'{device_decisions=}')

    # get the reflected (CTRL) and measured (SIFT) qubits

    ctrl_qubits = []

    for (idx, decesion) in enumerate(device_decisions):
        if decesion == 0:
            ctrl_qubits.append(idx)

    # print(f'{ctrl_qubits=}')
    sift_qubits = []

    for (idx, decesion) in enumerate(device_decisions):
        if decesion == 1:
            sift_qubits.append(idx)

    # print(f'{sift_qubits=}')

    z_sift = [sift_qubits[i] for i in range(len(sift_qubits)) if cc_basis[sift_qubits[i]] == 0]

    # print(f'{z_sift=}')
    
    # SIFT by device

    for idx in sift_qubits:
        circuit.measure(idx, idx)
    
    # measurement of sifted qubits by device

    result_device = execute(circuit, backend=simulator, shots=1).result()
    count_device = result_device.get_counts(circuit)

    device_measured_value = list(count_device.keys())[0][::-1]
    
    circuit.barrier()

    # measurement of reflected qubits by control centre

    for idx in ctrl_qubits:
        if cc_basis[idx] == 1:
            circuit.h(idx)
        circuit.measure(idx, idx)

    result_ctrl = execute(circuit, backend=simulator, shots=1).result()
    count_ctrl = result_ctrl.get_counts(circuit)

    return circuit

circuit_drawer(sqkd(), output='mpl', filename='sqkd.png')

