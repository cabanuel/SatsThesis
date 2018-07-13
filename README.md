# SatsThesis
## Low bandwidth, ligthweight transport layer protocol for nanosatellites

Done as a requirement for master's thesis work at the Naval Postgraduate School.

Available: https://calhoun.nps.edu/handle/10945/56101

Abstract:

*Nanosatellites provide a light, efficient, and cost-effective way for research institutions to carry out experiments in low Earth orbit. These satellites frequently use the ultra-high and very high frequency bands to transfer their data to the ground stations, and oftentimes will use internet protocol and Transmission Control Protocol as a standard for communication to ensure the arrival and integrity of the data transmitted. Due to bandwidth limitations and signal noise, these connection-based protocols end up accruing a large data bandwidth cost in headers and retransmissions. Furthermore, due to connection unreliability, encryption and integrity checks present a challenge. The aim of this thesis is to develop a software-based low-bandwidth reliable network protocol that can support a cryptographic system for encrypted communications using commercial off-the-shelf components. This protocol reduces the data overhead, retains the retransmission functionality and integrates support for a cryptographic system. This thesis develops the encryption mechanism, assesses its resilience to error propagation, and develops the protocol to work over a simulated network. The result of the study is a proof of concept that the protocol design is feasible, applicable, and could be used as a communication standard in future projects.*

## Repository Contents

### Ver0.1.1
Directory containing the latest version of the communication protocol (version 0.1.1). This version is the proof of concept that the communication protocol is feasible and can be implemented.

This directory contains Sat.py, which is used to simulate the communications package on the nanosatellite device, and can transmit files of arbitrary size using the mechanisms described in the thesis document. This directory also contains GroundStation.py which is used to simulate the communications package utilized by the ground station to communicate with the nanosatellite device. GroundStation.py can receive files from Sat.py, and can also handle the requests made to the nanosatellite. This proof of concept is done utilizing Python 3.5

Additionally, the directory also contains the proof of concept one-time-pad encryption testbed, encryptorTestBed.py. This was used to test and provide metrics of different encryption mechanisms, including the one-time-pad encryption mechanism suggested by the thesis. 

### code
Directory containing unstable versions of Sat.py, GoundStation.py, and other testing scripts. These were the development versions which could be unstable or unpredictable. 

### littleBits
Unrelated code used as local scratch for testing of scripts and penetration testing an unrelated device that I came accross while exploring hardware for the thesis.

### writing
Location for all of the thesis writing done in Microsoft Word. this directory includes proposals, different revisions of the thesis, and a bibliography.
