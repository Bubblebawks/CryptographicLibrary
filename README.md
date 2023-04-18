# CryptographicLibrary

Created by : Gil Rabara, Vivian Tran, Andrew Nguyen 

*** Objective ***
Implement (in Java) a library and an app for asymmetric encryption
and digital signatures at the 256-bit security level

*** Algorithms ***
- SHA-3 derived function KMACXOF256;
- ECDHIES encryption and Schnorr signatures;

*** PART 1: Symmetric cryptography ***

*** Services the app must offer for part 1: ***

The app does not need to have a GUI (a command line interface is acceptable),
but it must offer the following services in a clear and simple fashion (each item
below is one of the project parts). See the detailed specifications below:

- [10 points] Compute a plain cryptographic hash of a given file (this requires
implementing and testing cSHAKE256 and KMACXOF256 first).
    - BONUS [5 points] Compute a plain cryptographic hash of text input by the user
directly to the app (instead of having to be read from a file).
- [10 points] Compute an authentication tag (MAC) of a given file under a given
passphrase.
    - BONUS [5 points] Compute an authentication tag (MAC) of text input by the
user directly to the app (instead of having to be read from a file) under a given
passphrase.
- [10 points] Encrypt a given data file symmetrically under a given passphrase.
- [10 points] Decrypt a given symmetric cryptogram under a given passphrase.

*** Grading *** 
The main class of your project (the one containing the main() method) must be
called Main and be declared in file Main.java. You will be docked 5 points if the 
main method is missing/malformed, or defined/duplicated in a different class, or 
if the class containing it is not called Main or defined in a different source.

All your classes must be defined without a PACKAGE clause (that is, they must
be in the default, unnamed package). You will be docked 1 point for each source
file containing a PACKAGE clause.

You must include instruction on the use of your application and how to obtain
the above services as part of your report. You will be docked 20 points if the
report is missing for each project or if it does not match the observed
behavior of your application.

Remember that you will be docked 5 points for any .class, .jar or .exe file
contained in the ZIP file you turned in.

*** Submission ***
- Report: Describing our solutions for each part (typeset in PDF)
- For each part of the project, all source files and the report must be in a single ZIP
- Cite all material we use that is not our own work