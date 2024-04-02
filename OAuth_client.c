#include "OAuth.h"
#include "assert.h"

#define BUFF_SIZE 100
#define EMPTY_STRING ""
#define USER_NOT_FOUND "USER_NOT_FOUND"
#define REQUEST_DENIED "REQUEST_DENIED"
#define TOKEN_EXPIRED "TOKEN_EXPIRED"

// structura folosita pentru a tine evidenta datelor clientilor
struct client_info_struct {
	char *client_id;
	char *access_token;
	char *refresh_token;
	char *auth_token;
	int valability;
	int auto_refresh;
};

// functie care primeste o linie din fisierul de input si imparte in 3 tokeni
// continutul ei
void get_tokens(char *line, char **token1, char **token2, char **token3)
{
	char **tokens = malloc(BUFF_SIZE * sizeof(char *));
	char *s = line;
	char *curr = strtok(s, ",");
	int i = 0;

	while (curr) {
		tokens[i] = malloc((strlen(curr) + 1) * sizeof(char));
		strcpy(tokens[i], curr);
		i++;
		curr = strtok(NULL, ",");
	}

    *token1 = strdup(tokens[0]);
	*token2 = strdup(tokens[1]);
    *token3 = strdup(tokens[2]);

    for (int i = 0; i < 3; i++) {
        free(tokens[i]);
    }
	free(tokens);
}

void generate_access_token(char *client_id, char *auto_refresh_token, CLIENT *cl,
				   struct client_info_struct *client_info, int *client_info_index)
{
	// declar structura folosita ca paramentru pentru functia
	// request_authorization si ii populez campul.
	struct req_auth_req req_auth;
	req_auth.cliend_id = client_id;

	client_info[*client_info_index].client_id = client_id;

	// fac requestul catre server pentru a obtine tokenul de autorizare
	struct req_auth_resp *auth_resp;
	auth_resp = request_authorization_1(&req_auth, cl);

	// verific raspunsul intors de la server
	if (strcmp(auth_resp->error_message, USER_NOT_FOUND) == 0) {
		free(auth_resp->error_message);
		free(auth_resp->auth_token);
		printf("%s\n", USER_NOT_FOUND);
	} else {
		char *auth_token = auth_resp->auth_token;
		client_info[*client_info_index].auth_token = auth_token;

		// declar structura folosita ca paramentru pentru functia
		// approve_request_token si ii populez campul
		struct approve_req_token_req req_approve_token;
		req_approve_token.auth_token = auth_token;

		// fac requestul catre server pentru a obtine tokenul semnat
		struct approve_req_token_resp *resp_approve_token;
		resp_approve_token = approve_request_token_1(&req_approve_token, cl);

		int perms = resp_approve_token->auth_signed_token.perms;
		int auto_refresh = atoi(auto_refresh_token);

		// declar structura folosita ca parametru pentru functia
		// request_access_token si ii populez campurile
		struct req_access_token_req req_access_token;
		req_access_token.cliend_id = client_id;
		req_access_token.auto_refresh = auto_refresh;
		req_access_token.auth_signed_token.auth_token = auth_token;
		req_access_token.auth_signed_token.perms = perms;

		client_info[*client_info_index].auto_refresh = auto_refresh;

		// fac requestul catre server pentru a obtine access_tokenul
		struct req_access_token_resp *resp_access_token;
		resp_access_token =  request_access_token_1(&req_access_token, cl);

		// verific raspunsul intors de la server
		if (strcmp(resp_access_token->error_message, REQUEST_DENIED) == 0) {
			free(resp_access_token->error_message);
			free(resp_access_token->access_token);
			free(resp_access_token->refresh_token);
			printf("%s\n", REQUEST_DENIED);
		} else {
			char *access_token = resp_access_token->access_token;
			char *refresh_token = resp_access_token->refresh_token;
			int valability = resp_access_token->valability;

			client_info[*client_info_index].access_token = access_token;
			client_info[*client_info_index].refresh_token = refresh_token;
			client_info[*client_info_index].valability = valability;
			(*client_info_index)++;

			auto_refresh == 0 ? printf("%s -> %s\n", auth_token, access_token) : 
								printf("%s -> %s,%s\n", auth_token, access_token, refresh_token);
		}
	}
}

void file_action(char *client_id, char *action, char *resource, CLIENT *cl,
				 struct client_info_struct *client_info, int *client_info_index)
{
	// declar structura folosita ca paramentru pentru functia
	// validate_delegated_action si ii populez campurile
	struct validate_delegated_action_req validate_action_req;
	validate_action_req.operation_type = action;
	validate_action_req.resource = resource;

	char *refresh_token = EMPTY_STRING;
	char *access_token = EMPTY_STRING;
	
	// obtin access si refresh tokenul clientului dat ca paramentru in functie
	for (int i = 0; i < *client_info_index; i++) {
		if (strcmp(client_info[i].client_id, client_id) == 0) {
			access_token = client_info[i].access_token;
			refresh_token = client_info[i].refresh_token;
		}
	}

	validate_action_req.access_token = access_token;

	// fac requestul la server pentru a obtine mesajul de succes sau eroare
	struct validate_delegated_action_resp *validate_action_resp;
	validate_action_resp = validate_delegated_action_1(&validate_action_req, cl);

	// daca token-ul a expirat dar clientul a optat sa aibe refresh token
	// generez alta pereche de access si refresh token
	if (strcmp(validate_action_resp->message, TOKEN_EXPIRED) == 0 &&
		strcmp(refresh_token, EMPTY_STRING) != 0) {
			struct req_refresh_token_req refresh_token_req;
			refresh_token_req.refresh_token = refresh_token;

			struct req_refresh_token_resp *refresh_token_resp;
			refresh_token_resp = request_refresh_token_1(&refresh_token_req, cl);

			char *new_access_token = refresh_token_resp->new_access_token;
			char *new_refresh_token = refresh_token_resp->new_refresh_token;

			// actualizez noile informatii despre access_token si refresh_token
			for (int i = 0; i < *client_info_index; i++) {
				if (strcmp(client_info[i].client_id, client_id) == 0) {
					client_info[i].access_token = new_access_token;
					client_info[i].refresh_token = new_refresh_token;
				}
			}
			validate_action_req.access_token = new_access_token;
			validate_action_resp = validate_delegated_action_1(&validate_action_req, cl);
		}
	printf("%s\n", validate_action_resp->message);
}

int main (int argc, char *argv[])
{
	if (argc < 3) {
		printf ("usage: %s host fisier_operatii\n", argv[0]);
		exit (1);
	}

	// creeare client
	CLIENT *cl = clnt_create (argv[1], OAUTH_PROG, OAUTH_VERS, "udp");
	if (cl == NULL) {
		clnt_pcreateerror (argv[1]);
		exit (1);
	}

	// vectori de structuri de tip client_info pentru a retine 
	// informatii (id, access_token, refresh_token, etc) despre fiecare utilizator
	struct client_info_struct client_info[BUFF_SIZE];
	int client_info_index = 0;

	// deschide fisierul de operarii
	FILE *operation_file = fopen(argv[2], "r");
	assert(operation_file);

	char line[BUFF_SIZE];
	char **tokens;
	char *token1, *token2, *token3;
	
	// parcurge fiecare linie din fisier si o imparte in 3 tokeni
	// 1. id ul clientului
	// 2. REQUEST / tipul de actiune
	// 3. daca e nevoie sau nu de token de refresh / resura accesata
	while (fgets(line, BUFF_SIZE, operation_file) != NULL) {
		get_tokens(line, &token1, &token2, &token3);

        if (token3[strlen(token3) - 1] == '\n') {
			token3[strlen(token3) - 1] = '\0';
		}
	
		if (strcmp(token2, "REQUEST") == 0) {
			generate_access_token(token1, token3, cl, client_info, &client_info_index);
		} else {
			file_action(token1, token2, token3, cl, client_info, &client_info_index);
		}
	}

	free(token1);
	free(token2);
	free(token3);

	fclose(operation_file);
	clnt_destroy(cl);
	exit (0);
}
