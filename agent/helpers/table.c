/* table.c */

#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <assert.h>

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "table.h"

mib_handler *
get_table_handler(table_registration_info *tabreq) {
  mib_handler *ret = NULL;
  
  if (!tabreq) {
		snmp_log(LOG_INFO, "get_table_handler(NULL) called\n");
		return NULL;
  }
  
  ret = create_handler("table", table_helper_handler);
  if (ret) {
		ret->myvoid = (void *) tabreq;
		tabreq->number_indexes = count_varbinds(tabreq->indexes);
  }
  return ret;
}

    
int
register_table(handler_registration *reginfo,
               table_registration_info *tabreq) {
  inject_handler(reginfo, get_table_handler(tabreq));
  return register_handler(reginfo);
}

static void
table_helper_cleanup(agent_request_info *reqinfo, request_info *request,
                     int status ) {

	set_request_error(reqinfo, request, status);
	if (request->parent_data) {
		snmp_free_varbind(((table_request_info*)request->parent_data)->indexes);
		free(request->parent_data);
		request->parent_data = NULL;
  }
}


unsigned int
closest_column( unsigned int current, column_info *valid_columns )
{
  unsigned int closest = 0;
	char done = 0;
  char idx;
  assert( valid_columns != NULL );
  
  do {
	
		if (valid_columns->isRange) {
	  
			if (current < valid_columns->details.range[0]) {
				if (valid_columns->details.range[0] < closest) {
					closest = valid_columns->details.range[0];
				}
			} else if (current <= valid_columns->details.range[1]) {
				closest = current;
				done = 1;  /* can not get any closer! */
			}
	  
		} /* range */
		else { /* list */
	  
			if (current < valid_columns->details.list[ 0 ]) {
				if (valid_columns->details.list[ 0 ] < closest)
					closest = valid_columns->details.list[ 0 ];
				continue;
			}
	  
			if (current > valid_columns->details.list[ valid_columns->list_count ])
				continue; /* not in list range. */
					 
			for (idx=0; idx < valid_columns->list_count; ++idx ) {
				if (current == valid_columns->details.list[ idx ]) {
					closest = current;
					done = 1; /* can not get any closer! */
					break; /* for */
				} else if ( current < valid_columns->details.list[ idx ]) {
					if (valid_columns->details.list[ idx ] < closest)
						closest = valid_columns->details.list[ idx ];
					break; /* list should be sorted */
				}
			}/* for */
	  
		} /* list */

		valid_columns = valid_columns->next;

  } while( ! done && valid_columns );
  
  return closest;
}

int
table_helper_handler(
										 mib_handler               *handler,
										 handler_registration      *reginfo,
										 agent_request_info        *reqinfo,
										 request_info              *requests) {
  
  request_info              *request;
		
  table_registration_info   *tbl_info;
  int oid_index_pos = reginfo->rootoid_len + 2;
  int oid_column_pos = reginfo->rootoid_len + 1;
  int tmp_idx, tmp_len;
  int incomplete, out_of_range;
  int status = SNMP_ERR_NOERROR, need_processing = 0;
  oid *tmp_name;
  table_request_info        *tbl_req_info;
  struct variable_list      *vb;
    
  tbl_info = (table_registration_info *) handler->myvoid;

  if ( (!handler->myvoid) || (!tbl_info->indexes) ) {
		snmp_log(LOG_INFO, "improperly registered table found\n");
	
		/* XXX-rks: unregister table? */
		return SNMP_ERR_GENERR;
  }

	/*
	 * if the agent request info has a state reference, then
	 * this is a later pass of a set request and we can
	 * skip all the lookup stuff.
	 */
	if (reqinfo->state_reference) {
		if (MODE_IS_SET(reqinfo->mode)) {
			return call_next_handler(handler, reginfo, reqinfo, requests);
		}
		else {
#warning "XXX-rks: memory leak. add cleanup handler?"
			reqinfo->state_reference = NULL;
		}
	}


  /*
   * loop through requests
   */

  DEBUGMSGTL(("helper:table", "Got request:\n"));
  for(request = requests;
			request;
			request = request->next) {
		struct variable_list *var = request->requestvb;

		assert(request->parent_data == NULL);

		DEBUGMSGTL(("helper:table", "  oid:"));
		DEBUGMSGOID(("helper:table", var->name, var->name_length));
		DEBUGMSG(("helper:table", "\n"));

		if (request->status)
			continue;
		++need_processing;

		/* this should probably be handled further up */
		if ( (reqinfo->mode == MODE_GET) &&
				 (var->type != ASN_NULL) ) { /* valid request if ASN_NULL */
			DEBUGMSGTL(("helper:table", "  GET var type is not ASN_NULL\n" ));
                        set_request_error(reqinfo, request,
                                          SNMP_ERR_WRONGTYPE);
			continue;
		}

		/*
	 * check to make sure its in table range
	 */

		out_of_range = 0;
		/* if our root oid i > var->name and this is not a GETNEXT, */
		/* then the oid is out of range                             */
		if (snmp_oid_compare(reginfo->rootoid,reginfo->rootoid_len,
												 var->name,reginfo->rootoid_len) > 0) {
			if (reqinfo->mode == MODE_GETNEXT) {
				if (var->name != var->name_loc)
					free(var->name);
				snmp_set_var_objid(var, reginfo->rootoid, reginfo->rootoid_len );
			} else {
				DEBUGMSGTL(("helper:table", "  oid is out of range.\n"));
				out_of_range = 1;
			}
		}
		/* if var->name is longer than the root, make sure it is  */
		/* table.1 (table.ENTRY).                                 */
		else if ( (var->name_length > reginfo->rootoid_len) &&
							(var->name[reginfo->rootoid_len] != 1) ) {
			if ( (var->name[reginfo->rootoid_len] < 1) &&
					 (reqinfo->mode == MODE_GETNEXT) ) {
				var->name[reginfo->rootoid_len] = 1;
				var->name_length = reginfo->rootoid_len;
			} else {
				out_of_range = 1;
				DEBUGMSGTL(("helper:table", "  oid is out of range.\n"));
			}
		}
		/* if it is not in range, then remove it from the request list  */
		/* because we can't process it. If the request is not a GETNEXT */
		/* then set the error to NOSUCHOBJECT so nobody else wastes time*/
		/* trying to process it.                                        */
		if (out_of_range) {
			DEBUGMSGTL(("helper:table", "  Not processed.\n"));
			if (reqinfo->mode != MODE_GETNEXT) {
				table_helper_cleanup(reqinfo, request,SNMP_ERR_NOSUCHNAME);
			}
			continue;
		}

	
		/*
	 * Check column ranges; set-up to pull out indexes from OID.
	 */

		incomplete = 0;
		tbl_req_info = SNMP_MALLOC_TYPEDEF(table_request_info);
		tbl_req_info->indexes = snmp_clone_varbind(tbl_info->indexes);
		tbl_req_info->number_indexes = 0; /* none yet */
		if (var->name_length <= oid_column_pos) { /* none available */
			tbl_req_info->colnum = tbl_info->min_column;
			tbl_req_info->index_oid_len = 0;
		} else {
			if( var->name[oid_column_pos] < tbl_info->min_column ) {
				/* fix column, truncate useless index info */
				var->name[oid_column_pos] = tbl_info->min_column;
				var->name_length = oid_column_pos;
			}
			else if( var->name[oid_column_pos] > tbl_info->max_column ) {
				/* this is out of range...  remove from requests, free memory */
				DEBUGMSGTL(("helper:table", "  oid is out of range. Not processed.\n"));
				if (reqinfo->mode != MODE_GETNEXT) {
					table_helper_cleanup(reqinfo, request,SNMP_ERR_NOSUCHNAME);
				}
				continue;
			}
			/* use column verification */
			else if( tbl_info->valid_columns ) {
				tbl_req_info->colnum = closest_column(var->name[oid_column_pos],
																							tbl_info->valid_columns );
				if (tbl_req_info->colnum == 0)
					continue;
				if (tbl_req_info->colnum != var->name[oid_column_pos] ) {
					/* different column! truncate useless index info */
					var->name[oid_column_pos] = tbl_req_info->colnum;
					var->name_length = oid_column_pos;
				}
			}
	
			tbl_req_info->colnum = var->name[oid_column_pos];
			tbl_req_info->index_oid_len = var->name_length - oid_index_pos;
			assert(tbl_req_info->index_oid_len < MAX_OID_LEN);
			memcpy(tbl_req_info->index_oid,&var->name[oid_index_pos],
						 tbl_req_info->index_oid_len*sizeof(oid) );
			tmp_name = tbl_req_info->index_oid;
		}
		if (tbl_req_info->index_oid_len==0) {
			incomplete = 1;
			tmp_len = -1;
		}
		else
			tmp_len = tbl_req_info->index_oid_len;


	/*
	 * for each index type, try to extract the index from var->name
	 */

		for(tmp_idx=0,vb=tbl_req_info->indexes;
				tmp_idx < tbl_info->number_indexes;
				++tmp_idx,vb=vb->next_variable) {
			if (incomplete && tmp_len) {
				/* incomplete/illegal OID, set up dummy 0 to parse */
				DEBUGMSGTL(("helper:table", "  oid indexes not complete.\n" ));
				/* no sense in trying anymore if this is a GET/SET. */
				if (reqinfo->mode != MODE_GETNEXT) {
					table_helper_cleanup(reqinfo, requests,SNMP_ERR_NOSUCHNAME);
				}
				tmp_len = 0;
				tmp_name = (oid*) &tmp_len;
			}
			/* try and parse current index */
			if (parse_one_oid_index(&tmp_name, &tmp_len,
															vb, 1) != SNMPERR_SUCCESS) {
				incomplete = 1;
				tmp_len = -1; /* is this necessary? Better safe than sorry */
			}
			else {
				/* do not count incomplete indexes */
				if( incomplete )
					continue;
				++tbl_req_info->number_indexes; /* got one ok */
				if (tmp_len <= 0) {
					incomplete = 1;
					tmp_len = -1; /* is this necessary? Better safe than sorry */
				}
			}
		} /* for loop */
 
	
		/*
	 * do we have sufficent index info to continue?
	 */
	
		if ((reqinfo->mode != MODE_GETNEXT) &&
				((tbl_req_info->number_indexes != tbl_info->number_indexes) ||
				 (tmp_len!=-1)))
			{
				table_helper_cleanup(reqinfo, request, SNMP_ERR_NOSUCHNAME);
			}

		DEBUGIF("helper:table") {
			int count;
			char buf[SPRINT_MAX_LEN];
			DEBUGMSGTL(("helper:table", "  column: %d, indexes: %d\n",
									tbl_req_info->colnum, tbl_req_info->number_indexes));
			for(vb = tbl_req_info->indexes, count = 0;
					vb && count < tbl_info->number_indexes;
					count++, vb = vb->next_variable) {
				sprint_by_type(buf, vb, 0, 0, 0);
				DEBUGMSGTL(("helper:table", "    index: type=%d, value=%s\n",
										vb->type, buf));
			}
		}

		/* save table_req_info */
		request->parent_data = (void *) tbl_req_info;

  } /* for each request */


  /*
   * call our child access function
   */
	if (need_processing)
		status = call_next_handler(handler, reginfo, reqinfo, requests);
    
  return status;
}

int
table_build_oid(handler_registration *reginfo,
								request_info *reqinfo,
								table_request_info *table_info)
{
  oid tmpoid[MAX_OID_LEN];
  struct variable_list *var;

  if (!reginfo || !reqinfo || !table_info)
		return SNMPERR_GENERR;
    
  memcpy(tmpoid, reginfo->rootoid, reginfo->rootoid_len * sizeof(oid));
  tmpoid[reginfo->rootoid_len] = 1; /* .Entry */
  tmpoid[reginfo->rootoid_len+1] = table_info->colnum; /* .column */
    
  var = reqinfo->requestvb;
  if (build_oid(&var->name, &var->name_length,
								tmpoid, reginfo->rootoid_len+2,
								table_info->indexes)
			!= SNMPERR_SUCCESS)
		return SNMPERR_GENERR;

  return SNMPERR_SUCCESS;
}

int
table_build_oid_from_index(handler_registration *reginfo,
																request_info *reqinfo,
																table_request_info *table_info)
{
  oid tmpoid[MAX_OID_LEN];
  struct variable_list *var;
	int len;

  if (!reginfo || !reqinfo || !table_info)
		return SNMPERR_GENERR;
	
	var = reqinfo->requestvb;
	len = reginfo->rootoid_len;
  memcpy(tmpoid, reginfo->rootoid, len * sizeof(oid));
  tmpoid[len++] = 1; /* .Entry */
  tmpoid[len++] = table_info->colnum; /* .column */
	memcpy( &tmpoid[len], table_info->index_oid,
					table_info->index_oid_len * sizeof(oid));
	len += table_info->index_oid_len;
  snmp_clone_mem( (void**)&var->name, tmpoid, len * sizeof(oid) );
	var->name_length = len;

  return SNMPERR_SUCCESS;
}

int
table_build_result(handler_registration *reginfo,
									 request_info *reqinfo,
									 table_request_info *table_info, u_char type,
									 u_char *result, size_t result_len) {
    
  struct variable_list *var;

  if (!reqinfo || !table_info)
		return SNMPERR_GENERR;
    
  var = reqinfo->requestvb;

  if (var->name != var->name_loc)
		free(var->name);
  var->name = NULL;

  if (table_build_oid(reginfo, reqinfo, table_info) != SNMPERR_SUCCESS)
		return SNMPERR_GENERR;

  snmp_set_var_typed_value(var, type, result, result_len);
              
  return SNMPERR_SUCCESS;
}

int
update_variable_list_from_index( table_request_info *tri )
{
	return parse_oid_indexes(tri->index_oid, tri->index_oid_len,
													 tri->indexes);
}

int
update_indexes_from_variable_list( table_request_info *tri )
{
	return build_oid_noalloc(tri->index_oid, sizeof(tri->index_oid),
													 &tri->index_oid_len, NULL, 0, tri->indexes);
}
