Introduction to Computer Security
MPCS 56511

Access Check Utility
Project 3

Spencer Zepelin

August 18, 2019

------------------


Building and Running the Program
---

A makefile has been provided to compile the program in an 
environment with a C compiler capable of supporting pragma 
directives with access to the BSD version of the string.h 
header. The program "access_check" can be 
compiled by simply entering the command "make".

There are two operation modes in which the program can be run. 
The mode will automatically be selected by the number of 
arguments passed, namely, whether or not a filepath to a batch 
file is included.

1. Interactive Mode - Parses the named group file and ACL and 
prompts the user to enter an access query of the form <READ | 
WRITE | EXECUTE> <user> and prints either "GRANTED" or 
"DENIED" in accordance with the access algorithm before 
prompting the user for the next query. The program can be 
terminated at any time by entering "exit" when prompted for a 
query.

Command:
./access_check check GROUPFILE ACL

2. Batch Mode - Parses the named group file and ACL and loops 
through each line in the batch file. Treating each line as a 
seperate query, the program writes either "GRANTED: <query>" 
or "DENIED: <query>" to the corresponding line in the 
"output.txt" file.

Command:
./access_check check GROUPFILE ACL BATCHFILE

If an input has more than two tokens, the program--in either 
mode--will treat only the first two tokens as the query. Thus, 
if user 'alice' has READ access, an entry of...

	READ alice foobar

...will result in 'GRANTED: READ alice' in an output file or 
simply 'GRANTED' in interactive mode.

Other non-conforming inputs will be handled cleanly. In 
interactive mode, the program will return an error message 
indicating the proper input format and await a new query. In 
batch mode, the program will instead write...

INVALID: <query>

...to the output file where QUERY is the command given on the 
corresponding line of the batch file.


Testing
---

Testing was performed on the departmental Linux machines 
against provided test files and contrived examples. In all 
instances, the program performed successfully in both modes of 
operation. For convenience, the commands "make interactive" 
and "make batch" will test the program in interative and batch 
mode, respectively, using the files "group.txt" and "acl1.txt" 
provided in the "testfiles" directory.

Program Design 
---

The main function resides in the "access_check.c" file. 
Regardless of the mode in which it is run, the program begins 
by attempting to parse both the ACL and group file. The parsed 
data is then stored in the acl and groupfile structs, 
respectively. These data structures are defined in 
"access_support.h" where helper functions are also declared. 
Helper functions are defined in "access_support.c".

The parser is capable of handling empty group files and empty 
groups, though it assumes that empty groups are terminated 
with a colon and that there are no blank lines in the group 
file. It also assumes that each group will be of the form:

GROUPNAME:PASSWORD:GROUPID:[USERS]

Additionally, the parser assumes that an ACL file will have 
the following structure:

# file: FILENAME
# owner: OWNER
# group: GROUPNAME
user::---
[NAMEDUSERS]
group::---
[NAMEDGROUPS]
[MASK]
other::---

The memory-safe function strlcpy from the bsd version of 
string.h was used throughout. I have attempted to include 
robust, if verbose, error handling and input sanitization. The 
parser has been designed to throw errors and safely exit the 
program if it fails to parse either file. As an additional 
feature, more robust parsing to support non-conforming group 
files and ACLs could be added in the future. 

The access check algorithm has been designed to execute in 
accordance with the steps outlined in the POSIX ACL man file. 
Briefly, it runs as follows:

1. If the queried user is the owner, owner permissions are 
checked.
2. If not, if the user is named in the ACL, that user's 
permissions and the mask (if it exists in the ACL), are 
checked.
3. If not, if the named user is in a group named in the ACL, 
that group's permissions and the mask are checked.
4. If the user is in multiple group and all groups deny 
access, access is denied. If any group grants access and the 
mask does as well, access is granted.
5. Otherwise, other access is checked.

While the main function remains slightly longer, a support 
file and header were added to help improve readability and 
keep the main file at a reasonable length. Further abstraction 
by means of functionalization of processes performed by both 
modes could be performed to improve the readability of the 
main program.
