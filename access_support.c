#include "access_support.h"
#include <stdio.h>
#include <stdlib.h>
#include <bsd/string.h>

#define MAXLINE 256
#define MAXUSERGROUP 100
#define MAXNAME 256
#define TRUE 1
#define FALSE 0

void print_permission(char permchar){
	if (permchar != '-'){
		printf("GRANTED\n");
	} else {
		printf("DENIED\n");
	}
}

void write_permission(FILE* f, char permchar, char* command, char* user){
	if (permchar != '-'){
		fprintf(f, "GRANTED: %s %s\n", command, user);
	} else {
		fprintf(f, "DENIED: %s %s\n", command, user);
	}
}


// NOTE: position count starts at 0!
// position2 is represented as the number of places AFTER position 1
int get_token(char* line, char** output, char** output2, int position1, int position2, char* delim){
	char* token_control;
	token_control = strtok(line, delim);
	if (token_control == NULL){
		// Failure
		return 1;
	}
	for (int i = 0; i < position1; i++){
		token_control = strtok(NULL, delim);
		if (token_control == NULL){
			// Failure
			return 1;
		}
	}
	strlcpy(*output, token_control, MAXLINE);
	if (output2 != NULL){
		for (int j = 0; j < position2; j++){
			token_control = strtok(NULL, delim);
			if (token_control == NULL){
				// Failure
				return 1;
			}
		}
		strlcpy(*output2, token_control, MAXLINE);
	}
	return 0;
}

int in_group(char* members, char* user){
	char buf[MAXNAME];
	strlcpy(buf, members, MAXNAME);
	char* token = strtok(buf, ",");
	while (token != NULL){
		if (! strcmp(token, user)){
			// User found
			return TRUE;
		}
		token = strtok(NULL, ",");
	}
	return FALSE;
}

int acl_init(ACL* acl){
	acl->filename = (char*) malloc(sizeof(char) * MAXNAME);
	if ( acl->filename == NULL ){
		return 1;
	}
	acl->owner = (char*) malloc(sizeof(char) * MAXNAME);
	if ( acl->owner == NULL ){
		return 1;
	}
	acl->group = (char*) malloc(sizeof(char) * MAXNAME);
	if ( acl->group == NULL ){
		return 1;
	}
	acl->named_users = (char**) malloc(sizeof(char*) * MAXUSERGROUP);
	if ( acl->named_users == NULL ){
		return 1;
	}
	acl->named_groups = (char**) malloc(sizeof(char*) * MAXUSERGROUP);
	if ( acl->named_groups == NULL ){
		return 1;
	}
	for (int i = 0; i < MAXUSERGROUP; i++){
		acl->named_users[i] = (char*) malloc(sizeof(char) * MAXNAME);
		acl->named_groups[i] = (char*) malloc(sizeof(char) * MAXNAME);
		if ( acl->named_users[i] == NULL || acl->named_groups[i] == NULL ){
			return 1;
		}
	}
	acl->user_permissions = (char*) malloc(sizeof(char) * (3 * MAXUSERGROUP + 1));
	if ( acl->user_permissions == NULL ){
		return 1;
	}
	acl->group_permissions = (char*) malloc(sizeof(char) * (3 * MAXUSERGROUP + 1));
	if ( acl->group_permissions == NULL ){
		return 1;
	}
	acl->num_named_users = 0;
	acl->num_named_groups = 0;
	acl->mask = (char*) malloc(sizeof(char) * 4);
	if ( acl->mask == NULL ){
		return 1;
	}
	strlcpy(acl->mask, "rwx", 4);
	acl->other = (char*) malloc(sizeof(char) * 4);
	if ( acl->other == NULL ){
		return 1;
	}
	return 0;
}

void free_acl(ACL* acl){
	for (int i = 0; i < MAXUSERGROUP; i++){
		free(acl->named_users[i]);
		free(acl->named_groups[i]);
	}
	free(acl->filename);
	free(acl->owner);
	free(acl->group);
	free(acl->named_users);
	free(acl->named_groups);
	free(acl->user_permissions);
	free(acl->group_permissions);
	free(acl->mask);
	free(acl->other);
}

int grouplist_init(Grouplist* grouplist){
	grouplist->num_valid_groups = 0;
	grouplist->valid_groups = (char**) malloc(sizeof(char*) * MAXUSERGROUP);
	if (grouplist->valid_groups == NULL){
		return 1;
	}
	grouplist->group_members = (char**) malloc(sizeof(char*) * MAXUSERGROUP);
	if (grouplist->group_members == NULL){
		return 1;
	}
	for (int i = 0; i < MAXUSERGROUP; i++){
		grouplist->valid_groups[i] = (char*) malloc(sizeof(char) * MAXNAME);
		grouplist->group_members[i] = (char*) malloc(sizeof(char) * MAXNAME);
		if (grouplist->valid_groups[i] == NULL || grouplist->group_members[i] == NULL){
			return 1;
		}
	}
	return 0;
}

void free_grouplist(Grouplist* grouplist){
	for (int i = 0; i < MAXUSERGROUP; i++){
		free(grouplist->valid_groups[i]);
		free(grouplist->group_members[i]);
	}
	free(grouplist->valid_groups);
	free(grouplist->group_members);
}
