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
n = 4

# delta parameter for sqkd
delta = 1/8

# (Z-)error threshold for CTRL for sqkd
p_ctrl = 0.5

# (Z-)error threshold for SIFT for sqkd
p_test = 0.5

def createBellStates(state_number, qubit1, qubit2, circuit):
    '''
    state_number (int): bell state based on above cell
    qubit1 (int), qubit2 (int): indices of entangled qubits
    circuit (QuantumCircuit): circuit under consideration

    return QuantumCircuit: updated quantum circuit
    '''
    if state_number == 0:
        pass
    elif state_number == 1:
        circuit.x(qubit1)
    elif state_number == 2:
        circuit.x(qubit2)
    elif state_number == 3:
        circuit.x(qubit1)
        circuit.x(qubit2)
    circuit.h(qubit1)
    circuit.cnot(qubit1, qubit2)
    return circuit

def createDecoyQubits(key, bit, idx, circuit):
    '''
    key (str): securely shared key
    bit (int): 0 or 1
    idx (int): index of the decoy bit
    circuit (QuantumCircuit): circuit under consideration

    return QuantumCircuit: updated quantum circuit
    '''
    if bit:
        circuit.x(idx)
    if key[2*idx:2*idx+2] in {"10", "11"}:
        circuit.h(idx)
    return circuit

def sq_auth(key):
    '''
    key (string): key of the device to be authenticated

    return (bool bool): (is classical entity legal, is quantum entity legal)
    '''

    # print(f'{key=}')

    n_prime = n//2  # since size of the key in paper is 2*n
    # we define n' as 2*n' = n

    # STEP 1: Preparation

    circuit = QuantumCircuit(n_prime*2, n_prime*2)

    # Even bits = S_H
    # Odd bits = S_T

    initial_bell_state_number = list(np.random.randint(0, 4, size=(n_prime)))
    # print(f'{initial_bell_state_number=}')

    # n_prime*2 for n bell states

    # generating random n' bell states
    for i in range(n_prime):
        circuit = createBellStates(initial_bell_state_number[i], 2*i, 2*i+1, circuit)

    # STEP 2: Eavesdropping detection

    ## generating n'/2 decoy qubits

    decoy_circuit = QuantumCircuit(n_prime//2, n_prime//2)

    decoy_init = np.random.randint(0, 2, size=(n_prime//2))

    # print(f'{decoy_init=}')

    for i in range(n_prime//2):
        decoy_circuit = createDecoyQubits(key, decoy_init[i], i, decoy_circuit)


    for i in range(n_prime//2):
        if key[2*i:2*i+2] in {"10", "11"}:
            decoy_circuit.h(i)
        decoy_circuit.measure(i, i)
    
    decoy_result = execute(decoy_circuit, backend=simulator, shots=1).result()
    decoy_count = decoy_result.get_counts(decoy_circuit)
    decoy_measured_values = [int(b) for b in list(decoy_count.keys())[0][::-1]]

    # print(f'{decoy_measured_values=}')

    for i in range(n_prime//2):
        if decoy_measured_values[i] != decoy_init[i]:
            print("AUTH FAILED")
            return (False, False)

    # STEP 3: Measurement

    for i in range(n_prime*2):
        circuit.measure(i, i)

    result = execute(circuit, backend=simulator, shots=1).result()
    count = result.get_counts(circuit)
    measured_values = [int(b) for b in list(count.keys())[0][::-1]]

    # STEP 4: XOR operation

    ## Create RB

    RB = []

    for i in range(1, n, 2):
        RB.append(measured_values[i])
    # print(f'{RB=}')
    
    ## Create IA

    RA = []

    for i in range(0, n, 2):
        RA.append(measured_values[i])
    # print(f'{RA=}')

    ## Create RA*

    RAstar = []

    for i in range(n_prime):
        if RB[i] == 0:
            if initial_bell_state_number[i] in {0, 1}:
                RAstar.append(0)
            else:
                RAstar.append(1)
        elif RB[i] == 1:
            if initial_bell_state_number[i]  in {0, 1}:
                RAstar.append(1)
            else:
                RAstar.append(0)
    # print(f'{RAstar=}')


    ## Create RB*

    RBstar = []

    for i in range(n_prime):
        if RA[i] == 0:
            if initial_bell_state_number[i]  in {0, 1}:
                RBstar.append(0)
            else:
                RBstar.append(1)
        elif RA[i] == 1:
            if initial_bell_state_number[i]  in {0, 1}:
                RBstar.append(1)
            else:
                RBstar.append(0)
    # print(f'{RBstar=}')

    ## Create IA, IAstar, IB, IBstar
    IA = []
    IB = []
    IAstar = []
    IBstar = []

    for i in range(n_prime):
        IA.append(RA[i]^int(key[i]))
        IB.append(RB[i]^int(key[i]))
        IAstar.append(RAstar[i]^int(key[i]))
        IBstar.append(RBstar[i]^int(key[i]))

    # print(f'{IA=}')
    # print(f'{IB=}')
    # print(f'{IAstar=}')
    # print(f'{IBstar=}')

    # STEP 5: Authentication

    classical_auth, quantum_auth = 1, 1

    for i in range(n_prime):
        if IA[i] != IAstar[i]:
            quantum_auth = 0
        if IB[i] != IBstar[i]:
            classical_auth = 0
    
    # print(f'{measured_values=}')

    # print(circuit.draw())
    # print(decoy_circuit.draw())
    return (circuit, decoy_circuit)

circuit, decoy_circuit = sq_auth("1011")

circuit_drawer(circuit, output='mpl', filename='sqma.png')
circuit_drawer(decoy_circuit, output='mpl', filename='decoy.png')

