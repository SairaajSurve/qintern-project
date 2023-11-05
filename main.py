# %% [markdown]
# # Smart meters using Semi Quantum Key Distribution

# %%
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

# %%
import qiskit
qiskit.__qiskit_version__

# %%
simulator = Aer.get_backend('qasm_simulator')

# %% [markdown]
# Variable definition

# %%
# size of INFO BITS for sqkd
n = 4

# delta parameter for sqkd
delta = 1/8

# (Z-)error threshold for CTRL for sqkd
p_ctrl = 0.5

# (Z-)error threshold for SIFT for sqkd
p_test = 0.5

# path to control centre and nan database
cc_nan_db_path = './database/control_center_nan_database.txt'

# path to control centre and smart meter database
cc_sm_db_path = './database/control_center_smart_meter_database.txt'

# path to nan and smart meter database
nan_sm_db_path = './database/nan_sm_database.txt'

# %% [markdown]
# ## File handling

# %% [markdown]
# ## Helper functions

# %% [markdown]
# Function to add NAN gateway for Control Center

# %%
def addNewNANForCC(Inan, SharedKey):
    '''
    Inan (string): Identity of NAN
    SharedKey(string): Shared secret key
    '''
    # Check if both parameters are passed
    if Inan == None or SharedKey == None:
        print(f"NAN addition failed:{Inan=}:{SharedKey=}")
        return False
    
    # Check if NAN identity exists
    with open(cc_nan_db_path, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_Inan, _SharedKey] = row.split(':')
            if _Inan == Inan:
                print(f"NAN addition failed:{Inan=} already exists")
    
    # Add new NAN

    with open(cc_nan_db_path, "a") as file:
        file.write(f'{Inan}:{SharedKey}\n')
    return True

# %% [markdown]
# Function to add Smart Meter for Control Center

# %%
def addNewSMForNAN(PSID, SharedKey):
    '''
    PSID(string): pseudo identity for smart meter
    SharedKey(string): Shared session key
    '''
    # Check if both parameters are passed
    if PSID == None or SharedKey == None:
        print(f"SM addition failed:{PSID=}:{SharedKey=}")
        return False

    PSID = str(list(PSID))
    # Check if SM identity exists
    with open(nan_sm_db_path, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_PSID, _SharedKey, md] = row.split(':')
            if _PSID == PSID:
                print(f"SM addition failed:{PSID=} already exists")

    # Add new SM

    with open(nan_sm_db_path, "a") as file:
        file.write(f'{PSID}:{SharedKey}:{0}\n')
    
    return True

# %%
def addNewSMForCC(Ism, SharedKey):
    '''
    Ism (string): Identity of SM
    SharedKey(string): Shared secret key
    '''
    # Check if both parameters are passed
    if Ism == None or SharedKey == None:
        print(f"SM addition failed:{Ism=}:{SharedKey=}")
        return False
    
    # Check if SM identity exists
    with open(cc_sm_db_path, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_Ism, _Iencsm, _SharedKey] = row.split(':')
            if _Ism == Ism:
                print(f"SM addition failed:{Ism=} already exists")
    
    # Generate Iencsm

    biometric = np.random.randint(2, size=len(Ism))

    Iencsm = ""

    for i in range(len(Ism)):
        Iencsm += str(int(biometric[i])^(not int(Ism[i])))

    # Add new SM

    with open(cc_sm_db_path, "a") as file:
        file.write(f'{Ism}:{Iencsm}:{SharedKey}\n')
    
    return True

# %% [markdown]
# Function to add Smart Meter for NAN

# %%
def getSMForNAN(PSID):
    '''
    PSID(str): PSID of SM
    '''

    with open(nan_sm_db_path, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_PSID, _SharedKey, _md] = row.split(':')
            if _PSID == PSID:
                return (_PSID, _SharedKey, _md)
    print("Failed to get SM")
    return (None, None, None)

# %% [markdown]
# Function to get data of Smart Meter for Control Center

# %%
def getSMForCC(Iencsm):
    '''
    Iencsm(str): encrypted biometric of smart meter
    '''

    with open(cc_sm_db_path, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_Ism, _Iencsm, _SharedKey] = row.split(':')
            if _Iencsm == Iencsm:
                return (_Ism, _Iencsm, _SharedKey)
    print("Failed to get SM")
    return (None, None, None)

# %% [markdown]
# Function to get data of NAN gateway for Control Center

# %%
def getNANForCC(Inan):
    '''
    Inan(str): biometric of nan gateway
    '''
    with open(cc_nan_db_path, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_Inan,  _SharedKey] = row.split(':')
            if _Inan == Inan:
                return (_Inan, _SharedKey)
    print("Failed to get NAN")
    return (None, None)

# %% [markdown]
# ## Phase 1

# %% [markdown]
# Function for encoding bits in 0/1 or +/- state for sqkd

# %%
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

# %% [markdown]
# Function for performing SQKD dnd registering new device

# %%
def sqkdPhase1(choice):
    '''
    choice (int):
    1 = save in cc_nan database
    2 = save in cc_sm database

    Saves data in database if SQKD is successfull
    
    return bool: True if SQKD is successfull else False
    '''

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


    # print(f'{device_measured_value=}')

    ######### PENDING ####################
    # reorder the reflected (CTRL) qubits

    ###################################

    # measurement of reflected qubits by control centre

    for idx in ctrl_qubits:
        if cc_basis[idx] == 1:
            circuit.h(idx)
        circuit.measure(idx, idx)

    result_ctrl = execute(circuit, backend=simulator, shots=1).result()
    count_ctrl = result_ctrl.get_counts(circuit)

    ctrl_measured_value = list(count_ctrl.keys())[0][::-1]

    # print(f'{ctrl_measured_value=}')

    # calculating error for ctrl

    z_error_ctrl = 0
    x_error_ctrl = 0
    len_z = 0
    len_x = 0

    for idx in ctrl_qubits:
        if cc_basis[idx] == 0:
            if message[idx] != int(ctrl_measured_value[idx]):
                # print("z")
                # print(idx)
                z_error_ctrl += 1
            len_z += 1
        elif cc_basis[idx] == 1:
            if message[idx] != int(ctrl_measured_value[idx]):
                # print("x")
                # print(idx)
                x_error_ctrl += 1
            len_x += 1

    # print(f'{z_error_ctrl/len_z=}')
    # print(f'{x_error_ctrl/len_x=}')

    if z_error_ctrl/len_z < p_ctrl and x_error_ctrl/len_x < p_ctrl:

        # select n random sift bits in z basis as test bits

        test_bits = set()
        while len(test_bits) < n:
            test_bits = set(np.random.choice(z_sift, size=n))
        
        # print(f'{test_bits=}')

        # defining remaning string

        v = []

        for idx in z_sift:
            if idx not in test_bits:
                v.append(idx)

        # print(f'{v=}')
        # calculating z error for sift

        z_error_test = 0

        for idx in test_bits:
            if int(device_measured_value[idx]) != int(ctrl_measured_value[idx]):
                z_error_test += 1

        # print(f'{z_error_test/len(test_bits)=}')

        if z_error_test/len(test_bits) < p_test and len(v) >= n:

            info_bits = v[:n]

            info = ""

            for idx in info_bits:
                info += device_measured_value[idx]

            # print(f'{info=}')

            # Apply hash to function to info
            sk = hashlib.sha512(info.encode('utf-8')).hexdigest()

            # print(f'{sk=}')

            ######## SAVE IN FILE ###############

            # Generate Identity

            temp_Ix = np.random.randint(2, size=n)

            Ix = ""

            for i in range(len(temp_Ix)):
                Ix += str(temp_Ix[i])

            if choice == 1:
                if addNewNANForCC(Ix, info):
                    return True
            if choice == 2:
                if addNewSMForCC(Ix, info):
                    return True

    print("SQKD FAILED")
    return False

# %% [markdown]
# ## Phase 2

# %% [markdown]
# Function to generate PreAuthReqSM

# %%
def genPreAuthReqSM(Iencsm, TS):
    '''
    Iencsm(str): encrypted biometric of smart meter
    TS(float): time of initiation of protocol
    '''

    [Ism, Iencsm, SharedKey] = getSMForCC(Iencsm)

    if Ism != None and Iencsm != None and SharedKey != None:
        PreAuthReqSM = {
            "HMAC": hmac.new(SharedKey.encode("utf-8"), Iencsm.encode("utf-8"), hashlib.sha256).hexdigest(),
            "Iencsm": Iencsm,
            "TS": TS,
            "SharedKey": SharedKey
        }
        return PreAuthReqSM
    print("Failed to create PreAuthReqSM")
    return None

# %% [markdown]
# Function to generate PreAuthReqNAN

# %%
def genPreAuthReqNAN(Iencsm, Inan, TS):
    '''
    Iencsm(str): encrypted biometric of smart meter
    Inan(str): biometric of nan gateway
    TS(float): time of initiation of protocol
    '''

    PreAuthReqSM = genPreAuthReqSM(Iencsm, TS)
    [Inan,  SharedKey] = getNANForCC(Inan)

    if Inan != None and SharedKey != None and PreAuthReqSM != None:
        PreAuthReqNAN = {
            "PreAuthReqSM": PreAuthReqSM,
            "HMAC": hmac.new(SharedKey.encode("utf-8"), Inan.encode("utf-8"), hashlib.sha256).hexdigest(),
            "Inan": Inan,
            "TS": TS,
            "SharedKey": SharedKey
        }
        return PreAuthReqNAN
    print("Failed to create PreAuthReqNAN")
    return None

# %% [markdown]
# Semi-Quantum Mutual Identity Authentication Using Bell States

# %% [markdown]
# $$ |\varphi^{\pm}> = \frac{1}{\sqrt{2}}(|00>\pm|11>) (0, 1)$$
# $$ |\phi^{\pm}> = \frac{1}{\sqrt{2}}(|01>\pm|10>) (2, 3)$$

# %% [markdown]
# Functon to create bell states for authentication

# %%
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

# %% [markdown]
# Function to create decoy qubits based on secret key

# %%
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

# %% [markdown]
# Function for semi quantum authentication

# %%
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

    ###### Pending ######
    # reordering
    #####################

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

    # print(f'{(classical_auth, quantum_auth)=}')

    return (classical_auth, quantum_auth)

# %% [markdown]
# Function for comparing HMAC of NAN

# %%
def verifyNANHMAC(hmacValue, Inan):
    '''
    hmacValue (string): value of hmac
    Inan(str): biometric of nan gateway
    '''
    _Inan, _SharedKey = getNANForCC(Inan)
    if _SharedKey != None and _Inan != None:
        return hmac.new(_SharedKey.encode("utf-8"), _Inan.encode("utf-8"), hashlib.sha256).hexdigest() == hmacValue
    print("Verify NAN HMAC Failed")
    return False

# %% [markdown]
# Function for comparing HMAC of SM

# %%
def verifySMHMAC(hmacValue, Iencsm):
    '''
    hmacValue (string): value of hmac
    Iencsm(str): encrypted biometric of smart meter
    '''
    _Ism, _Iencsm, _SharedKey = getSMForCC(Iencsm)
    if _SharedKey != None and _Iencsm != None:
        return hmac.new(_SharedKey.encode("utf-8"), _Iencsm.encode("utf-8"), hashlib.sha256).hexdigest() == hmacValue
    print("Verify SM HMAC Failed")
    return False

# %% [markdown]
# Function for authenticating SM

# %%
def authSM(Iencsm, Inan, TS):
    '''
    Iencsm(str): encrypted biometric of smart meter
    Inan(str): biometric of nan gateway
    TS(float): time of initiation of protocol
    '''

    # getting PreAuthReq Payloads
    PreAuthReqNAN = genPreAuthReqNAN(Iencsm, Inan, TS)
    PreAuthReqSM = PreAuthReqNAN["PreAuthReqSM"]
    
    # verifying HMAC of NAN

    if verifyNANHMAC(PreAuthReqNAN["HMAC"], Inan):

        # authenticating NAN gateway
        cc_auth, nan_auth = sq_auth(PreAuthReqNAN["SharedKey"])
        
        # print(f'{cc_auth=}:{nan_auth=}')

        if cc_auth and nan_auth:
            
            # verifying HMAC of sm

            if verifySMHMAC(PreAuthReqSM["HMAC"], Iencsm):

                # authenticating SM

                cc_auth, sm_auth = sq_auth(PreAuthReqSM["SharedKey"])

                # print(f'{cc_auth=}:{sm_auth=}')

                return cc_auth and sm_auth

    print("Auth failed")
    return False

# %% [markdown]
# ## Phase 3

# %% [markdown]
# Function to perfrom SQKD for phase 3

# %%
def sqkdPhase3(PSID):
    '''
    PSID(string): pseudo identity for smart meter

    Saves data in database if SQKD is successfull
    
    return bool: True if SQKD is successfull else False
    '''

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


    # print(f'{device_measured_value=}')

    ######### PENDING ####################
    # reorder the reflected (CTRL) qubits

    ###################################

    # measurement of reflected qubits by control centre

    for idx in ctrl_qubits:
        if cc_basis[idx] == 1:
            circuit.h(idx)
        circuit.measure(idx, idx)

    result_ctrl = execute(circuit, backend=simulator, shots=1).result()
    count_ctrl = result_ctrl.get_counts(circuit)

    ctrl_measured_value = list(count_ctrl.keys())[0][::-1]

    # print(f'{ctrl_measured_value=}')

    # calculating error for ctrl

    z_error_ctrl = 0
    x_error_ctrl = 0
    len_z = 0
    len_x = 0

    for idx in ctrl_qubits:
        if cc_basis[idx] == 0:
            if message[idx] != int(ctrl_measured_value[idx]):
                # print("z")
                # print(idx)
                z_error_ctrl += 1
            len_z += 1
        elif cc_basis[idx] == 1:
            if message[idx] != int(ctrl_measured_value[idx]):
                # print("x")
                # print(idx)
                x_error_ctrl += 1
            len_x += 1

    # print(f'{z_error_ctrl/len_z=}')
    # print(f'{x_error_ctrl/len_x=}')

    if z_error_ctrl/len_z < p_ctrl and x_error_ctrl/len_x < p_ctrl:

        # select n random sift bits in z basis as test bits

        test_bits = set()
        while len(test_bits) < n:
            test_bits = set(np.random.choice(z_sift, size=n))
        
        # print(f'{test_bits=}')

        # defining remaning string

        v = []

        for idx in z_sift:
            if idx not in test_bits:
                v.append(idx)

        # print(f'{v=}')
        # calculating z error for sift

        z_error_test = 0

        for idx in test_bits:
            if int(device_measured_value[idx]) != int(ctrl_measured_value[idx]):
                z_error_test += 1

        # print(f'{z_error_test/len(test_bits)=}')

        if z_error_test/len(test_bits) < p_test and len(v) >= n:

            info_bits = v[:n]

            info = ""

            for idx in info_bits:
                info += device_measured_value[idx]

            # print(f'{info=}')

            # Apply hash to function to info
            sk = hashlib.sha512(info.encode('utf-8')).hexdigest()

            # print(f'{sk=}')

            ######## SAVE IN FILE ###############

            if addNewSMForNAN(PSID, info):
                return True

    print("SQKD FAILED")
    return False

# %% [markdown]
# Function for AckPreAuthReqNAN generation

# %%
def genAckPreAuthReqNAN(Iencsm, Inan):
    '''
    Iencsm(str): encrypted biometric of smart meter
    Inan(str): biometric of nan gateway
    '''
    TS = time.time()
    if authSM(Iencsm, Inan, TS):

        tempR = np.random.randint(2, size=n)
        R = ""
        for i in range(n):
            R += str(tempR[i])

        [__, _, _SharedKey] = getSMForCC(Iencsm)

        while len(_SharedKey) < 16:
            _SharedKey = "0" + _SharedKey

        cipher = AES.new((_SharedKey).encode('utf-8'), AES.MODE_ECB)

        padded_data = Padding.appendPadding(
            Iencsm+R, blocksize=Padding.AES_blocksize, mode=0)
        PSID = cipher.encrypt(padded_data.encode("utf-8"))

        return {
            "PSID": PSID,
            "TS": TS
        }
    print("AckPreAuthReqNAN generation failed")
    return None

# %% [markdown]
# Function to store session key

# %%
def storeSessionKey(Iencsm, Inan):
    '''
    Iencsm(str): encrypted biometric of smart meter
    Inan(str): biometric of nan gateway
    '''
    AckPreAuthReqNAN = genAckPreAuthReqNAN(Iencsm, Inan)
    if AckPreAuthReqNAN != None:
        [__, _, _SharedKey] = getSMForCC(Iencsm)

        while len(_SharedKey) < 16:
            _SharedKey = "0" + _SharedKey

        cipher = AES.new(_SharedKey.encode('utf-8'), AES.MODE_ECB)

        decrypted_data = Padding.removePadding(
        cipher.decrypt(AckPreAuthReqNAN["PSID"]).decode(), mode=0)
        _Iencsm = decrypted_data[:4]

        if _Iencsm == Iencsm:
            AckPreAuthReqSM = {
                "AckPreAuthReqNAN": AckPreAuthReqNAN,
                "TS": time.time()
            }
            if AckPreAuthReqSM["TS"] - AckPreAuthReqNAN["TS"] <= 30*60*1000:
                if sqkdPhase3(AckPreAuthReqNAN["PSID"]):
                    return True
    print("Failed to store session key")
    return False

# %% [markdown]
# ## Phase 4

# %% [markdown]
# Function to generate BillReq

# %%
def getBillReq(SessionKey, PSID, MDCurr):
    '''
    SessionKey(str): SessionKey of Sm
    PSID(str): PSID of SM
    MDCurr(float): current metering data
    '''

    Tsm = time.time()
    MCU = {
        "MDCurr": MDCurr,
        "PSID": PSID,
        "Tsm": Tsm,
    }
    MSG = hmac.new(SessionKey.encode("utf-8"), str(MCU).encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "MSG": MSG,
        "MDCurr": MDCurr,
        "MCU": MCU,
        "PSID": PSID,
        "Tsm": Tsm,
    }

# %% [markdown]
# Function to update usage

# %%
def updateMD(PSID, MD):
    '''
    PSID(str): PSID of SM
    '''

    data = []

    with open(nan_sm_db_path, "r") as file:
        for row in file.read().split('\n')[:-1]:
            [_PSID, _SharedKey, _md] = row.split(':')
            if _PSID == PSID:
                _md = str(MD)
                row = ":".join([_PSID, _SharedKey, _md])
            data.append(row)
    
    with open(nan_sm_db_path, "w") as file:
        for row in data:
            file.write(f'{row}\n')
    return True

# %% [markdown]
# Function to get and generate bill

# %%
def getBill(SessionKey, PSID, MDCurr):
    '''
    SessionKey(str): SessionKey of Sm
    PSID(str): PSID of SM
    MDCurr(float): current metering data
    '''
    print(PSID)
    BillReq = getBillReq(SessionKey, PSID, MDCurr)
    print(SessionKey)
    [_, SessionKey, MDPrev] = getSMForNAN(PSID)
    print(SessionKey)
    _MCU = {
        "MDCurr": BillReq["MDCurr"],
        "PSID": BillReq["PSID"],
        "Tsm": BillReq["Tsm"],
    }
    print(str(_MCU).encode("utf-8"))
    print(str(BillReq["MCU"]).encode("utf-8"))
    
    _MSG = hmac.new(SessionKey.encode("utf-8"), str(_MCU).encode("utf-8"), hashlib.sha256).hexdigest()
    print(_MSG)
    print(BillReq["MSG"])
    if _MSG == BillReq["MSG"]:
        if updateMD(PSID, float(BillReq["MDCurr"])):
            return float(BillReq["MDCurr"]) - float(MDPrev)
    print("Unauthorised request")
    return None

# %% [markdown]
# ## Menu based cell

# %%
c = None

while c != 0:
    # print("0. Exit")
    # print("1. Add NAN")
    # print("2. Add SM")
    # print("3. Generate Session Key")
    # print("4. Get Bill")
    # c = int(input("Enter your choice: "))
    c = int(input())

    if c == 1:
        print(sqkdPhase1(1))
    if c == 2:
        print(sqkdPhase1(2))
    if c == 3:
        # Iencsm = input("Enter Iencsm")
        # Inan = input("Enter Inan")
        Iencsm = input()
        Inan = input()
        storeSessionKey(Iencsm, Inan)
    if c == 4:
        # Inan = input("Enter SessionKey")
        # PSID = input("Enter PSID")
        # MDCurr = input("Enter MDCurr")
        SessionKey = input()
        PSID = input()
        MDCurr = float(input())
        getBill(SessionKey, PSID, MDCurr)

# %% [markdown]
# ## Test cells

# %%
# print(storeSessionKey("0010", "0011"))

# %%
# getBill("0001", "[56, 50, 13, 126, 148, 182, 88, 188, 100, 148, 79, 205, 165, 13, 180, 188]", 200)


