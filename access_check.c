#include "access_support.h"
#include <stdio.h>
#include <stdlib.h>
#include <bsd/string.h>

#define MAXLINE 256
#define MAXUSERGROUP 100
#define MAXNAME 256
#define COMMANDLEN 10

#define READ 0
#define WRITE 1
#define EXECUTE 2

#define TRUE 1
#define FALSE 0

#define FILEEND -1

/******* Notes *********

ALG
Is user object owner? If so, check owner permissions. If not,
Is access type masked? If so, access is denied. If not,
Is user named in ACL? If so, check user access. If not,
Is user in group(s) named in ACL? If so, check if any group grants access.
If all groups deny access, access is denied. If any group grants access, access is granted.
If not in any group named in ACL, check other access.

ARGS
0 executable
1 "check"
2 groupfile
3 acl file
4 batchfile (OPTIONAL)

**********************/


/*** MAIN FUNCTION ***/
int main(int argc, char ** args){
	
	// Check for correct number of arguments
	if (argc < 4 || argc > 5){
		printf("\n---Invalid arguments---\nProgram should be run with the following arguments:\n    EXECUTABLE check GROUPFILE ACLFILE [BATCHFILE]\nNote: BATCHFILE is optional. Including it will process the queries in the file. Omitting it will cause the program to enter interactive mode.\n\n");
		return EXIT_SUCCESS;
	}

	// Open and check group and acl files
	FILE* group_file = fopen(args[2], "r"); 
	if (group_file == NULL){
		printf("Failure opening group file. Exiting.\n");
		return EXIT_SUCCESS;
	}
	FILE* acl_file = fopen(args[3], "r"); 
	if (acl_file == NULL){
		printf("Failure opening ACL file. Exiting.\n");
		fclose(group_file);
		return EXIT_SUCCESS;
	}

	// Declare acl object
	ACL acl;
	// Initialize and check acl object
	if ( acl_init(&acl) ){
		fclose(group_file);
		fclose(acl_file);
		printf("Error with memory allocation. Exiting.\n");
		return EXIT_SUCCESS;
	}
	// Declare grouplist object
	Grouplist grouplist;
	// Initialize and check grouplist object
	if ( grouplist_init(&grouplist) ){
		fclose(group_file);
		fclose(acl_file);
		free_acl(&acl);
		printf("Error with memory allocation. Exiting.\n");
		return EXIT_SUCCESS;
	}
	// Read variables
	char* line_buf[MAXLINE];
	size_t bufsize = MAXLINE;

	/* Parsing Group File */
	// Loop through lines of group file
	// getline will return -1 on EOF
	size_t length = getline(line_buf, &bufsize, group_file);
	while (length != FILEEND){
		// Validate that the group actually has members
		if (*(*line_buf + length - 2) != ':'){
			// get_token will return 1 on failure
			if (get_token(*line_buf, &grouplist.valid_groups[grouplist.num_valid_groups], &grouplist.group_members[grouplist.num_valid_groups], 0, 3, ":\n")){
				printf("Tokenization failure in group file. Exiting.\n");
				fclose(group_file);
				fclose(acl_file);
				free_grouplist(&grouplist);
				free_acl(&acl);
				return EXIT_SUCCESS;
			}
			// Increment number of valid groups
			grouplist.num_valid_groups++;
		}
		length = getline(line_buf, &bufsize, group_file);
	}

	/* Parsing ACL file */
	// Parse object filename
	getline(line_buf, &bufsize, acl_file);
	if (get_token(*line_buf, &acl.filename, NULL, 2, 0, " \n")){
		printf("Tokenization failure in ACL file. Exiting.\n");
		fclose(group_file);
		fclose(acl_file);
		free_grouplist(&grouplist);
		free_acl(&acl);
		return EXIT_SUCCESS;
	}
	// Parse object owner
	getline(line_buf, &bufsize, acl_file);
	if (get_token(*line_buf, &acl.owner, NULL, 2, 0, " \n")){
		printf("Tokenization failure in ACL file. Exiting.\n");
		fclose(group_file);
		fclose(acl_file);
		free_grouplist(&grouplist);
		free_acl(&acl);
		return EXIT_SUCCESS;
	}
	// Parse object group
	getline(line_buf, &bufsize, acl_file);
	if (get_token(*line_buf, &acl.group, NULL, 2, 0, " \n")){
		printf("Tokenization failure in ACL file. Exiting.\n");
		fclose(group_file);
		fclose(acl_file);
		free_grouplist(&grouplist);
		free_acl(&acl);
		return EXIT_SUCCESS;		
	}

	// Add named user permissions to struct
	getline(line_buf, &bufsize, acl_file);
	strlcpy(acl.named_users[0], acl.owner, MAXNAME);
	if (get_token(*line_buf, &acl.user_permissions, NULL, 1, 0, ":\n")){
		printf("Tokenization failure in ACL file. Exiting.\n");
		fclose(group_file);
		fclose(acl_file);
		free_grouplist(&grouplist);
		free_acl(&acl);
		return EXIT_SUCCESS;
	}
	acl.num_named_users = 1;
	// Get next line
	getline(line_buf, &bufsize, acl_file);

	// Continue parsing users
	while (*line_buf[0] == 'u'){
		// Get name of named user
		// Using "other" for convenience // TODO need alternative if not guaranteed an other entry
		if (get_token(*line_buf, &acl.named_users[acl.num_named_users], &acl.other, 1, 1, ":\n")){
			printf("Tokenization failure in ACL file. Exiting.\n");
			fclose(group_file);
			fclose(acl_file);
			free_grouplist(&grouplist);
			free_acl(&acl);
			return EXIT_SUCCESS;
		}
		strlcpy( &acl.user_permissions[acl.num_named_users * 3], acl.other, 4 );
		// Increment number of named users
		acl.num_named_users++;
		// Get next line
		getline(line_buf, &bufsize, acl_file);
	}

	// Add named group to struct
	strlcpy(acl.named_groups[0], acl.group, MAXNAME);
	if (get_token(*line_buf, &acl.group_permissions, NULL, 1, 0, ":\n")){
		printf("Tokenization failure in ACL file. Exiting.\n");
		fclose(group_file);
		fclose(acl_file);
		free_grouplist(&grouplist);
		free_acl(&acl);
		return EXIT_SUCCESS;
	}
	acl.num_named_groups = 1;
	// Get next line
	getline(line_buf, &bufsize, acl_file);
	// Continue parsing groups
	while (*line_buf[0] == 'g'){
		// Get name of named user
		// Using "other" for convenience // TODO need alternative if not guaranteed an other entry
		if (get_token(*line_buf, &acl.named_groups[acl.num_named_groups], &acl.other, 1, 1, ":\n")){
			printf("Tokenization failure in ACL file. Exiting.\n");
			fclose(group_file);
			fclose(acl_file);
			free_grouplist(&grouplist);
			free_acl(&acl);
			return EXIT_SUCCESS;
		}
		strlcpy( &acl.group_permissions[acl.num_named_groups * 3], acl.other, 4 );
		// Increment number of named users
		acl.num_named_groups++;
		// Get next line
		getline(line_buf, &bufsize, acl_file);
	}

	// Parse mask permissions
	if (*line_buf[0] == 'm'){
		if (get_token(*line_buf, &acl.mask, NULL, 1, 0, ":\n")){
			printf("Tokenization failure in ACL file. Exiting.\n");
			fclose(group_file);
			fclose(acl_file);
			free_grouplist(&grouplist);
			free_acl(&acl);
			return EXIT_SUCCESS;
		}
		getline(line_buf, &bufsize, acl_file);
	}
	
	// Parse other permissions
	if (get_token(*line_buf, &acl.other, NULL, 1, 0, ":\n")){
		printf("Tokenization failure in ACL file. Exiting.\n");
		fclose(group_file);
		fclose(acl_file);
		free_grouplist(&grouplist);
		free_acl(&acl);
		return EXIT_SUCCESS;
	}


	// Query variables
	char query_buf[MAXLINE];
	char command_string[COMMANDLEN];
	char user_string[MAXNAME];
	int finished;
	char* token_check;

/******************
 INTERACTIVE BRANCH 
 ******************/
	if (argc == 4){
		int exit = FALSE;
		while ( exit == FALSE ){
			finished = FALSE;
			printf("Enter your query:\n");
			// Will truncate any password >BUFF_SIZE chars
			fgets(query_buf, MAXLINE, stdin); 
			strtok(query_buf, " \n");
			strlcpy(command_string, query_buf, COMMANDLEN);
			// Ability to exit program on command
			if (! strcmp( command_string, "exit" )){
				exit = TRUE;
				continue;
			}
			token_check = strtok(NULL, " \n");
			// If no user supplied, generate error message
			if (token_check == NULL){
				printf("\n'%s' is not a valid query.\nQueries must be of the form:\nCOMMAND USER\nValid options for COMMAND are:\n\nREAD\nWRITE\nEXECUTE\n\nTo quit the program at any time, enter: exit\n", command_string);
				continue;
			}
			// User supplied; store in user_string
			strlcpy(user_string, token_check, MAXNAME);
			// NOTE: Program will only parse first two tokens. If third is given, it will ignore it
			int command = -1;
			if (! strcmp(command_string, "READ")){
				command = READ;
				// printf("checking read command\n");
			} else if (! strcmp(command_string, "WRITE")){
				command = WRITE;
				// printf("checking write command\n");
			} else if (! strcmp(command_string, "EXECUTE")){
				command = EXECUTE;
				// printf("checking EXECUTE command\n");
			} else {
				// If command is invalid, print error message and return to prompt
				printf("\n'%s' is not a valid command.\nQueries must be of the form:\nCOMMAND USER\nValid options for COMMAND are:\nREAD\nWRITE\nEXECUTE\n\nTo quit the program at any time, enter: exit\n", command_string);
				continue;
			}

			/* ALG 1 */ 
			// the effective user ID of the process matches the user ID of the file object owner
			if (! strcmp(user_string, acl.owner)){
				// User is owner; print permission and wait for next command
				print_permission(acl.user_permissions[command]);
			// User is not object owner
			} else {
				/* ALG 2 */
				// Check if user named in ACL
				// Loop starts at 1 because first user is owner
				for (int i = 1; i < acl.num_named_users; i++){
					// Check for named user
					if (! strcmp(user_string, acl.named_users[i])){
						// Named user found; this will prevent group and other from executing
						finished = TRUE;
						// Check mask permission
						if (acl.mask[command] != '-'){
							// Mask permits; check user permission
							print_permission(acl.user_permissions[(3*i) + command]);
						} else {
							// Mask denies
							printf("DENIED\n");
						}
						
					}
				}
				/* ALG3 */
				// Check group membership and if any membership grants is named and grants access
				// User permissions supercede group permissions
				int in_named_group = FALSE;
				// Don't execute if named user
				if ( finished == FALSE ){
					// Check group membership of user
					int k = 0;
					while ( k < grouplist.num_valid_groups && finished == FALSE){
						// Check if user is in group
						if (in_group(grouplist.group_members[k], user_string)){
							printf("USER %s is in group %s\n", user_string, grouplist.valid_groups[k]);
							// User is in group; check if group is named in ACL
							int l = 0;
							while ( l < acl.num_named_groups && finished == FALSE){
								// Check if group named
								if (! strcmp(grouplist.valid_groups[k], acl.named_groups[l])){
									// Control variable for Other permissions
									in_named_group = TRUE;
									// Group named; Check if mask permits
									if (acl.mask[command] != '-'){
										// Mask permits; check if group permits
										if (acl.group_permissions[(3*l) + command] != '-'){
											// Access granted; exit loops
											printf("GRANTED\n");
											finished = TRUE;
										}
									} else {
										// Mask does not permit access for users in named groups
										printf("DENIED\n");
										finished = TRUE;
									}
									
								}
								// Check for match with next group in named groups
								l++;
							}
						}
						// Check next group in grouplist
						k++;
					}
				} 
				// User is in a named group, but no group grants permission
				// Do not check other; DENIED
				if ( finished == FALSE && in_named_group == TRUE){
					finished = TRUE;
					printf("DENIED\n");
				}
				/* ALG 4 */
				// Check other for access
				if ( finished == FALSE ){
					print_permission(acl.other[command]);
				}
			}
		}
	}

/****************
 BATCHFILE BRANCH 
 ****************/
	else{
		// Open batch file
		FILE * batch_file = fopen(args[4], "r");
		if (batch_file == NULL){
			fclose(group_file);
			fclose(acl_file);
			free_grouplist(&grouplist);
			free_acl(&acl);			
			printf("Failure opening batch file. Exiting.\n");
			return EXIT_SUCCESS;
		}

		// Open results file
		FILE * results_file = fopen("output.txt", "w");
		if (results_file == NULL){
			fclose(batch_file);
			fclose(group_file);
			fclose(acl_file);
			free_grouplist(&grouplist);
			free_acl(&acl);			
			printf("Failure opening output file. Exiting.\n");
			return EXIT_SUCCESS;
		}
		// TODO check for successful file opens
		// Get line will return -1 on EOF
		while ( getline(line_buf, &bufsize, batch_file) >= 0 ){
			// Reset control variable
			finished = FALSE;
			// Save line_buf to write to file with result
			strlcpy(query_buf, *line_buf, MAXLINE);
			// Parse command
			token_check = strtok(query_buf, " \n");
			// If null pointer returned, generate invalid
			if (token_check == NULL){
				fprintf(results_file, "INVALID: %s\n", *line_buf);
				continue;
			}
			// Copy command into command_string
			strlcpy(command_string, query_buf, COMMANDLEN);
			// Parse user
			token_check = strtok(NULL, " \n");
			// If no user supplied, generate invalid
			if (token_check == NULL){
				fprintf(results_file, "INVALID: %s", *line_buf);
				continue;
			}
			// User supplied; store in user_string
			strlcpy(user_string, token_check, MAXNAME);
			// NOTE: Program will only parse first two tokens. If third is given, it will ignore it
			int command = -1;
			if (! strcmp(command_string, "READ")){
				command = READ;
			} else if (! strcmp(command_string, "WRITE")){
				command = WRITE;
			} else if (! strcmp(command_string, "EXECUTE")){
				command = EXECUTE;
			} else {
				// If command is invalid, print invalid
				fprintf(results_file, "INVALID: %s", *line_buf);
				continue;
			}

			/* ALG 1 */
			// The effective user ID of the process matches the user ID of the file object owner
			if (! strcmp(user_string, acl.owner)){
				// User is owner; write permission and proceed to next
				write_permission(results_file, acl.user_permissions[command], command_string, user_string);
			// User is not object owner
			} else {
				/* ALG 2 */
				// Check if user named in ACL
				// Loop starts at 1 because first user is owner
				for (int i = 1; i < acl.num_named_users; i++){
					// Check for named user
					if (! strcmp(user_string, acl.named_users[i])){
						// Named user found; this will prevent group and other from executing
						finished = TRUE;
						// Check mask permission
						if (acl.mask[command] != '-'){
							// Mask permits; check user permission
							write_permission(results_file, acl.user_permissions[(3*i) + command], command_string, user_string);
						} else {
							// Mask denies
							fprintf(results_file, "DENIED: %s %s\n", command_string, user_string);
						}
						
					}
				}
				/* ALG3 */
				// Check group membership and if any membership named and grants access
				// User permissions supercede group permissions
				int in_named_group = FALSE;
				// Don't execute if named user
				if ( finished == FALSE ){
					// Check group membership of user
					int k = 0;
					while ( k < grouplist.num_valid_groups && finished == FALSE){
						// Check if user is in group
						if (in_group(grouplist.group_members[k], user_string)){
							// User is in group; check if group is named in ACL
							int l = 0;
							while ( l < acl.num_named_groups && finished == FALSE){
								// Check if group named
								if (! strcmp(grouplist.valid_groups[k], acl.named_groups[l])){
									// Control variable for Other permissions
									in_named_group = TRUE;
									// Group named; Check if mask permits
									if (acl.mask[command] != '-'){
										// Mask permits; check if group permits
										if (acl.group_permissions[(3*l) + command] != '-'){
											// Access granted; exit loops
											fprintf(results_file, "GRANTED: %s %s\n", command_string, user_string);
											finished = TRUE;
										}
									} else {
										// Mask does not permit access for users in named groups
										fprintf(results_file, "DENIED: %s %s\n", command_string, user_string);
										finished = TRUE;
									}
									
								}
								// Check for match with next group in named groups
								l++;
							}
						}
						// Check next group in grouplist
						k++;
					}
				} 
				// User is in a named group, but no group grants permission
				// Do not check other; DENIED
				if ( finished == FALSE && in_named_group == TRUE){
					fprintf(results_file, "DENIED: %s %s\n", command_string, user_string);
					finished = TRUE;
				}
				/* ALG 4 */
				// Check other for access
				if ( finished == FALSE ){
					write_permission(results_file, acl.other[command], command_string, user_string);
				}
			}
		}
		// Close results and batch files; only executes on batch branch
		fclose(results_file);
		fclose(batch_file);
	}
/** PROGRAM TERMINATION **/
	// Close remaining files and free memory
	fclose(group_file);
	fclose(acl_file);
	free_grouplist(&grouplist);
	free_acl(&acl);
	return EXIT_SUCCESS;
}


