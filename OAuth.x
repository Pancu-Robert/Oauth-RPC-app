/* structuri folosite pentru request authorization */
/* contine doar un singur camp care este id ul clientului */
struct req_auth_req {
    string cliend_id<>;
};

/* contine tokenul de autorizare si mesajul de eroare in cazul in care*/
/* utilizatorul nu se afla in baza de date */
struct req_auth_resp {
    string auth_token<>;
    string error_message<>;
};

/* structuri folosite pentru approve req token */
/* contine tokenul de autorizare pentru a putea fi semnat sau nu de utilizator */
struct approve_req_token_req {
    string auth_token<>;
};

/* semnarea tokenului se face printr-o variabila. */
/* cand variabila este 1 tokenul este semnat, altfel nu este semnat */
struct signed_token {
    string auth_token<>;
    int perms;
};

/* contine tokenul de autorizare semnat sau nu */
struct approve_req_token_resp {
    struct signed_token auth_signed_token;
};

/* structuri folosite pentru request access token */
/* contine id ul de client, tokenul semnat si daca este nevoie de token de refresh */
struct req_access_token_req {
    string cliend_id<>;
    struct signed_token auth_signed_token;
    int auto_refresh;
};

/* contine tokenul de access la resurse, refresh tokenul (daca utilizatorul a optat */
/* pentru acest lucru), valabilitatea unui token si mesajul de eroare in cazul in*/
/* care tokenul de acces nu este semnat*/
struct req_access_token_resp {
    string access_token<>;
    string refresh_token<>;
    int valability;
    string error_message<>;
};

/* structuri folosite pentru request access token using refresh token */
/* pentru a genera refresh token nou avem nevoie de cel vechi*/
struct req_refresh_token_req {
    string refresh_token<>;
};

/*generarea de refresh token nou duce la generarea unui acces token nou */
struct req_refresh_token_resp {
    string new_access_token<>;
    string new_refresh_token<>;
};


/* structuri folosite pentru validate delegated action */
struct validate_delegated_action_req {
    string operation_type<>;
    string resource<>;
    string access_token<>;
};

/*contine mesajul de succes sau de eroare in functie de fiecare eroare*/
struct validate_delegated_action_resp {
    string message<>;
};

program OAUTH_PROG {
    version OAUTH_VERS {
        req_auth_resp request_authorization(req_auth_req) = 1;
        approve_req_token_resp approve_request_token(approve_req_token_req) = 2;
        req_access_token_resp request_access_token(req_access_token_req) = 3;
        req_refresh_token_resp request_refresh_token(req_refresh_token_req) = 4;
        validate_delegated_action_resp validate_delegated_action(validate_delegated_action_req) = 5;
    } = 1;
} = 0x32345678;