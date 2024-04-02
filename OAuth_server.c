#include "OAuth.h"
#include "token.h"
#include "assert.h"

#ifndef SIG_PF
#define SIG_PF void(*)(int)
#endif

#define EMPTY_STRING ""
#define USER_NOT_FOUND "USER_NOT_FOUND"
#define REQUEST_DENIED "REQUEST_DENIED"
#define TOKEN_EXPIRED "TOKEN_EXPIRED"
#define RESOURCE_NOT_FOUND "RESOURCE_NOT_FOUND"
#define OPERATION_NOT_PERMITTED "OPERATION_NOT_PERMITTED"
#define PERMISSION_GRANTED "PERMISSION_GRANTED"
#define PERMISSION_DENIED "PERMISSION_DENIED"

char **user_ids;
int number_of_users;

char **resources;
int number_of_resources;

char approvals[100][100];
int number_of_approvals;
int curr_approval = 0;

int valability;

struct users_aux_database {
	char *client_id;
	char *auth_token;
	char *permissions;
};

struct users_database {
	char *client_id;
	char *access_token;
	char *refresh_token;
	char *permissions;
	int valability;
};

struct users_aux_database users_aux_database[100];
int users_aux_database_index = 0;

struct users_database users_database[100];
int users_database_index = 0;

static void
oauth_prog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		req_auth_req request_authorization_1_arg;
		approve_req_token_req approve_request_token_1_arg;
		req_access_token_req request_access_token_1_arg;
		req_refresh_token_req request_refresh_token_1_arg;
		validate_delegated_action_req validate_delegated_action_1_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply (transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;

	case request_authorization:
		_xdr_argument = (xdrproc_t) xdr_req_auth_req;
		_xdr_result = (xdrproc_t) xdr_req_auth_resp;
		local = (char *(*)(char *, struct svc_req *)) request_authorization_1_svc;
		break;

	case approve_request_token:
		_xdr_argument = (xdrproc_t) xdr_approve_req_token_req;
		_xdr_result = (xdrproc_t) xdr_approve_req_token_resp;
		local = (char *(*)(char *, struct svc_req *)) approve_request_token_1_svc;
		break;

	case request_access_token:
		_xdr_argument = (xdrproc_t) xdr_req_access_token_req;
		_xdr_result = (xdrproc_t) xdr_req_access_token_resp;
		local = (char *(*)(char *, struct svc_req *)) request_access_token_1_svc;
		break;

	case request_refresh_token:
		_xdr_argument = (xdrproc_t) xdr_req_refresh_token_req;
		_xdr_result = (xdrproc_t) xdr_req_refresh_token_resp;
		local = (char *(*)(char *, struct svc_req *)) request_refresh_token_1_svc;
		break;

	case validate_delegated_action:
		_xdr_argument = (xdrproc_t) xdr_validate_delegated_action_req;
		_xdr_result = (xdrproc_t) xdr_validate_delegated_action_resp;
		local = (char *(*)(char *, struct svc_req *)) validate_delegated_action_1_svc;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t) _xdr_result, result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	return;
}

// verifica daca o aprobare este valida pentru o anumita resursa si o
// anumita operatie
int verify_approval(char *approval, char *resource, char *operation_type)
{
	char **approval_tokens = malloc(100 * sizeof(char *));
	char *s = strdup(approval);
	char *curr_token = strtok(s, ",");
	int k = 0;

	while (curr_token) {
		approval_tokens[k] = malloc((strlen(curr_token) + 1) * sizeof(char));
		strcpy(approval_tokens[k], curr_token);
		k++;
		curr_token = strtok(NULL, ",");
	}

	int ok = 0;

	for (int i = 0; i < k - 1; i++) {
		if (strcmp(approval_tokens[i], resource) == 0) {
			char *approval_resource = approval_tokens[i + 1];
			if (strchr(approval_resource, operation_type[0]) != NULL ||
                strchr(approval_resource, 'X') != NULL && operation_type[0] == 'E') {
                    ok = 1;
                }
		}
	}

	for (int i = 0; i < k; i++) {
		free(approval_tokens[i]);
	}
	free(approval_tokens);
	return ok;
}

req_auth_resp *
request_authorization_1_svc(req_auth_req *argp, struct svc_req *rqstp)
{
	static req_auth_resp result;

	char *client_id = argp->cliend_id;
	printf("BEGIN %s AUTHZ\n", client_id);

	// caut utilizatorul in baza de date din fisier
	// daca exista ii generez un token de autentificare
	// daca nu exista intorc un mesaj de eroare
	for (int i = 0; i < number_of_users; i++) {
		if (strcmp(user_ids[i], client_id) == 0) {
			char *auth_token = generate_access_token(client_id);
			result.auth_token = auth_token;
			result.error_message = EMPTY_STRING;

			users_aux_database[users_aux_database_index].client_id = strdup(client_id);
			users_aux_database[users_aux_database_index].auth_token = auth_token;
			users_aux_database[users_aux_database_index].permissions = EMPTY_STRING;
			users_aux_database_index++;
			return &result;
		}
	}
	result.auth_token = EMPTY_STRING;
	result.error_message = USER_NOT_FOUND;

	return &result;
}

approve_req_token_resp *
approve_request_token_1_svc(approve_req_token_req *argp, struct svc_req *rqstp)
{
	static approve_req_token_resp result;

	char *auth_token = argp->auth_token;
	result.auth_signed_token.auth_token = auth_token;

	// cauta tokenul de autorizare in baza de date auxiliara pentru a vedea
	// daca tokenul exista sau nu si salveaza indexul din baza de date.
	int pos = -1;
	for (int i = 0; i < users_aux_database_index; i++) {
		if (strcmp(users_aux_database[i].auth_token, auth_token) == 0) {
			pos = i;
		}
	}

	// daca s-a gasit tokenul se ataseaza permisiunile utilizatorului
	if (pos >= 0 ) {
		char *approval = strdup(approvals[curr_approval++]);
		if (strcmp(approval, "*,-") == 0) {
			result.auth_signed_token.perms = 0;
		} else {
			users_aux_database[pos].permissions = strdup(approval);
			result.auth_signed_token.perms = 1;
		}
	} else {
		result.auth_signed_token.perms = 0;
	}

	return &result;
}

req_access_token_resp *
request_access_token_1_svc(req_access_token_req *argp, struct svc_req *rqstp)
{
	static req_access_token_resp result;

	char *client_id = argp->cliend_id;
	char *auth_token = argp->auth_signed_token.auth_token;
	printf("  RequestToken = %s\n", auth_token);

	// daca tokenul de autorizare este semnat
	// si daca utilizatorul este deja in baza de date
	// generez un token de acces la resurse si stochez date despre utilizator
	// intr-o baza de date
	if (argp->auth_signed_token.perms == 1) {
		for (int i = 0; i < users_aux_database_index; i++) {
			if (strcmp(users_aux_database[i].client_id, client_id) == 0 &&
			    strcmp(users_aux_database[i].auth_token, auth_token) == 0) {
					char *perms = users_aux_database[i].permissions;
					char *access_token = generate_access_token(auth_token);

					result.access_token = access_token;
					result.error_message = EMPTY_STRING;
					result.valability = valability;

					users_database[users_database_index].access_token = access_token;
					users_database[users_database_index].client_id = strdup(client_id);
					users_database[users_database_index].permissions = perms;
					users_database[users_database_index].valability = valability;

					printf("  AccessToken = %s\n", access_token);
					int auto_refresh = argp->auto_refresh;

					if (auto_refresh == 0) {
						result.refresh_token = EMPTY_STRING;
						users_database[users_database_index].refresh_token = EMPTY_STRING;
					} else {
						char *refresh_token = generate_access_token(access_token);
						result.refresh_token = refresh_token;
						users_database[users_database_index].refresh_token = refresh_token;
						printf("  RefreshToken = %s\n", refresh_token);
					}

					users_database_index++;
					return &result;
				}
		}
	} 
	result.error_message = REQUEST_DENIED;
	result.access_token = EMPTY_STRING;
	result.refresh_token = EMPTY_STRING;
	result.valability = 0;

	return &result;
}

req_refresh_token_resp *
request_refresh_token_1_svc(req_refresh_token_req *argp, struct svc_req *rqstp)
{
	static req_refresh_token_resp  result;

	char *refresh_token = argp->refresh_token;

	// caut clientul in baza de date pentru a vedea daca exista
	// daca exista actualizez access si refresh tokenul
	for(int i = 0; i < users_database_index; i++) {
		if (strcmp(users_database[i].refresh_token, refresh_token) == 0) {
			printf("BEGIN %s AUTHZ REFRESH\n", users_database[i].client_id);
			char *new_access_token = generate_access_token(refresh_token);
			char *new_refresh_token = generate_access_token(new_access_token);

			users_database[i].access_token = new_access_token;
			users_database[i].refresh_token = new_refresh_token;
			users_database[i].valability = valability;

			result.new_access_token = new_access_token;
			result.new_refresh_token = new_refresh_token;

			printf("  AccessToken = %s\n", new_access_token);
			printf("  RefreshToken = %s\n", new_refresh_token);
			return &result;
		}
	}

	result.new_access_token = EMPTY_STRING;
	result.new_refresh_token = EMPTY_STRING;

	return &result;
}

validate_delegated_action_resp *
validate_delegated_action_1_svc(validate_delegated_action_req *argp, struct svc_req *rqstp)
{
	static validate_delegated_action_resp  result;
	char *access_token = argp->access_token;
	char *operation_type = argp->operation_type;
	char *resource = argp->resource;

	// cauta utilizatorul in baza de date
	for (int i = 0; i < users_database_index; i++) {
		if (strcmp(users_database[i].access_token, access_token) == 0) {
			int valab = users_database[i].valability;
			// daca utilizatorul nu are refresh token afisez eroare
			if (valab == 0) {
				if (strcmp(users_database[i].refresh_token, EMPTY_STRING) == 0) {
					printf("DENY (%s,%s,%s,%d)\n", operation_type, resource, EMPTY_STRING, 0);
				}
				result.message = TOKEN_EXPIRED;
				return &result;
			}
			valab--;
			users_database[i].valability = valab;

			// verific daca exista resura accesata de utilizator
			// in serverul de resurse
			int exists = 0;
			for (int i = 0; i < number_of_resources; i++) {
				if (strcmp(resources[i], resource) == 0) {
					exists = 1;
				}
			}
			if (exists == 0) {
				printf("DENY (%s,%s,%s,%d)\n", operation_type, resource,
					   access_token, users_database[i].valability);
					   result.message = RESOURCE_NOT_FOUND;
					   return &result;
			}

			char *approval = users_database[i].permissions;

			// nu perminte nicio operatie
			if (strcmp(approval, "*,-") == 0) {
				printf("DENY (%s,%s,%s,%d)\n", operation_type, resource,
					   access_token, users_database[i].valability);
				result.message = OPERATION_NOT_PERMITTED;
				return &result;
			}

			// apelez o functie care verifica daca operatia de acces la resursa
			// este valida
			if (verify_approval(approval, resource, operation_type)) {
				printf("PERMIT (%s,%s,%s,%d)\n", operation_type, resource,
					   access_token, users_database[i].valability);
						result.message = PERMISSION_GRANTED;
						return &result;
			} else {
				printf("DENY (%s,%s,%s,%d)\n", operation_type, resource,
						access_token, users_database[i].valability);
						result.message = OPERATION_NOT_PERMITTED;
						return &result;
			}
		}
	}
	printf("DENY (%s,%s,%s,%d)\n", operation_type, resource, EMPTY_STRING, 0);
	result.message = PERMISSION_DENIED;
	return &result;
}

// citeste datele din fisierul userIDs
void read_client_file(char *filename)
{
	FILE *client_file = fopen(filename, "r");
	assert(client_file);

	fscanf(client_file, "%d", &number_of_users);
	user_ids = malloc(number_of_users * sizeof(char *));

	for (int i = 0; i < number_of_users; i++) {
		char id[16];
		fscanf(client_file, "%s", id);

		user_ids[i] = malloc((strlen(id) + 1) * sizeof(char));
		strncpy(user_ids[i], id, strlen(id) + 1);
	}

	fclose(client_file);
}

// citeste datele din fisierul resources
void read_resources_file(char *filename)
{
	FILE *resources_file = fopen(filename, "r");
	assert(resources_file);

	fscanf(resources_file, "%d", &number_of_resources);
	resources = malloc(number_of_resources * sizeof(char *));

	for (int i = 0; i < number_of_resources; i++) {
		char resource[100];
		fscanf(resources_file, "%s", resource);

		resources[i] = malloc((strlen(resource) + 1) * sizeof(char));
		strncpy(resources[i], resource, strlen(resource) + 1);
	}

	fclose(resources_file);
}

// citeste datele din fisierul approvals
void read_approvals_file(char *filename)
{
	FILE *approvals_file = fopen(filename, "r");
	assert(approvals_file);

	char line[100];
	int approval_index = 0;

	while (fgets(line, 100, approvals_file) != NULL) {
		if (line[strlen(line) - 1] == '\n') {
            line[strlen(line) - 1] = '\0';
        }
		strcpy(approvals[approval_index++], line);
	}

	number_of_approvals = approval_index;
	
	fclose(approvals_file);
}

int main (int argc, char **argv)
{
	if (argc < 5)	 {
		printf ("usage: %s fisier_clienti fisier_resurse fisier_aprobari valabilitate_jetoane\n", argv[0]);
		exit (1);
	}

	setbuf(stdout, NULL);
	read_client_file(argv[1]);
	read_resources_file(argv[2]);
	read_approvals_file(argv[3]);
	valability = atoi(argv[4]);
	register SVCXPRT *transp;

	pmap_unset (OAUTH_PROG, OAUTH_VERS);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, OAUTH_PROG, OAUTH_VERS, oauth_prog_1, IPPROTO_UDP)) {
		fprintf (stderr, "%s", "unable to register (OAUTH_PROG, OAUTH_VERS, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, OAUTH_PROG, OAUTH_VERS, oauth_prog_1, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (OAUTH_PROG, OAUTH_VERS, tcp).");
		exit(1);
	}

	svc_run ();
	// eliberez memoria pentru structurile auxiliare folosite
	for (int i = 0; i < number_of_users; i++) {
		free(user_ids[i]);
	}
	for (int i = 0; i < number_of_resources; i++) {
		free(resources[i]);
	}
	free(user_ids);
	free(resources);
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}