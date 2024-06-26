/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include <memory.h> /* for memset */
#include "OAuth.h"

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

req_auth_resp *
request_authorization_1(req_auth_req *argp, CLIENT *clnt)
{
	static req_auth_resp clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, request_authorization,
		(xdrproc_t) xdr_req_auth_req, (caddr_t) argp,
		(xdrproc_t) xdr_req_auth_resp, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

approve_req_token_resp *
approve_request_token_1(approve_req_token_req *argp, CLIENT *clnt)
{
	static approve_req_token_resp clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, approve_request_token,
		(xdrproc_t) xdr_approve_req_token_req, (caddr_t) argp,
		(xdrproc_t) xdr_approve_req_token_resp, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

req_access_token_resp *
request_access_token_1(req_access_token_req *argp, CLIENT *clnt)
{
	static req_access_token_resp clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, request_access_token,
		(xdrproc_t) xdr_req_access_token_req, (caddr_t) argp,
		(xdrproc_t) xdr_req_access_token_resp, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

req_refresh_token_resp *
request_refresh_token_1(req_refresh_token_req *argp, CLIENT *clnt)
{
	static req_refresh_token_resp clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, request_refresh_token,
		(xdrproc_t) xdr_req_refresh_token_req, (caddr_t) argp,
		(xdrproc_t) xdr_req_refresh_token_resp, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

validate_delegated_action_resp *
validate_delegated_action_1(validate_delegated_action_req *argp, CLIENT *clnt)
{
	static validate_delegated_action_resp clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, validate_delegated_action,
		(xdrproc_t) xdr_validate_delegated_action_req, (caddr_t) argp,
		(xdrproc_t) xdr_validate_delegated_action_resp, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}
