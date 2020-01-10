#pragma once

#include <stdio.h>

#define MAXLINE 256
#define MAXUSERGROUP 100
#define MAXNAME 256

struct ACL {
	char* filename;
	char* owner;
	char* group;
	char** named_users;
	char* user_permissions;
	unsigned int num_named_users;
	char** named_groups;
	char** group_members;
	char* group_permissions;
	unsigned int num_named_groups;
	char* mask;
	char* other;
};

typedef struct ACL ACL;

struct Grouplist {
	unsigned int num_valid_groups;
	char** valid_groups;
	char** group_members;
};

typedef struct Grouplist Grouplist;

void print_permission(char permchar);
void write_permission(FILE* f, char permchar, char* command, char* user);
int get_token(char* line, char** output, char** output2, int position1, int position2, char* delim);
int in_group(char* members, char* user);
int acl_init(ACL* acl);
void free_acl(ACL* acl);
int grouplist_init(Grouplist* grouplist);
void free_grouplist(Grouplist* grouplist);
