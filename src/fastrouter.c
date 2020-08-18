/*
 * pgbouncer-rr extension: FastRoutes
 *
 * Use PCRE regex library instead of Python function to determine routing rules
 */

#include <Python.h>
#include "bouncer.h"
#include <usual/pgutil.h>
#include <usual/fileutil.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "fastrouter.h"


// DB Users - '*' considered a wildcard
typedef struct {
	struct List  node;
	char        *username;
	struct List  rules_list;
} fr_user_t;

// Rules to apply for a user, referenced from a user record. 
typedef struct {
	struct List  node;
	char        *str;
	char        *dbname;
	pcre2_code  *code;
} fr_rule_t;

static bool         m_initialised = false;		// Has this module been initalised 
static struct List  m_users_list; 			// List of rules 
static char        *m_current_filename = NULL;		// Current configuration filename 


bool fr_initialise(void);
static fr_user_t *fr_get_user(const char *username);
static fr_user_t *fr_create_user(const char *username);
static void       fr_delete_users(void);

static pcre2_code *fr_compile(const char *pattern);
static void        fr_free_rule(pcre2_code *code);

static char*       fr_check(PgSocket *client, const char *username, const char *sql);
static bool        fr_trymatch(PgSocket *client, pcre2_code *regex, const char *sql);


/////////////////////////////////////////////////////////////////////////////
// PCRE / Regex compiling, freeing and matching
//

// Attempt to compile a PCRE rule 
static pcre2_code *fr_compile(const char *pattern) {

        int        errornumber;
        PCRE2_SIZE erroroffset;

        pcre2_code *re = pcre2_compile(
                (PCRE2_SPTR) pattern,  // the pattern 
                PCRE2_ZERO_TERMINATED, // indicates pattern is zero-terminated 
                0,                     // default options 
                &errornumber,          // for error number 
                &erroroffset,          // for error offset 
                NULL);                 // use default compile context 

        if (re == NULL) {
                PCRE2_UCHAR buffer[256];
                pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
                log_error("PCRE2 compilation failed at offset %d: %s\n", (int)erroroffset, buffer);
        }


        return re;
}

// Delete previously compiled PCRE rule 
static void fr_free_rule(pcre2_code *code) {
	pcre2_code_free(code);
}


// Test a compiled PCRE2 rule against a (SQL) string 

bool fr_trymatch(PgSocket *client, pcre2_code *regex, const char *sql) {

        pcre2_match_data *match_data;
	int rc;

        // Needed for storing results
        match_data = pcre2_match_data_create_from_pattern(regex, NULL);

        rc = pcre2_match(
                regex,                // the compiled pattern 
                (PCRE2_SPTR) sql,     // the subject string 
                PCRE2_ZERO_TERMINATED,// the length of the subject 
                0,                    // start at offset 0 in the subject 
                0,                    // default options 
                match_data,           // block for storing the result 
                NULL);                // use default match context 

        // Release stored results - only interested in the match / no match
        pcre2_match_data_free(match_data);


        // No match? (-1)
        if (rc== PCRE2_ERROR_NOMATCH) {
                return false;
        }


        // Error?
        if (rc<0) {
                // Log error.... return no match
	        slog_error(client, "Matching error %d", rc);
                return false;
        }
        else {  // Match
                return true;
        }
}




/////////////////////////////////////////////////////////////////////////////
// User list management....
//


// Find if we have a user in the list
static fr_user_t *fr_get_user(const char *username) {
	struct List *item;
	list_for_each(item, &m_users_list) {
		fr_user_t *user	 = container_of(item, fr_user_t, node);

		if (strcmp(username, user->username)==0) {
			return user;
		}
	}
	return NULL;
}


// Create a user, or return the existing one if present
static fr_user_t *fr_create_user(const char *username) {
	fr_user_t *user = NULL;

	/* Don't create if user exists */
	user = fr_get_user(username);
	if (user!=NULL) {
		return user;
	}

	/* Creating new user.... */
	user = (fr_user_t *) malloc(sizeof(fr_user_t));
	if (!user) {
		log_error("Out of memory");
		return NULL;
	}
	memset(user, 0, sizeof(fr_user_t));
	list_init(&user->node);
	list_init(&user->rules_list);
	user->username = strdup(username);
	if (!user->username) {
		log_error("Out of memory");
		free(user);
		return NULL;
	}
	list_append(&m_users_list, &user->node);

	return user;
}

// Delete all loaded users
static void fr_delete_users(void) {
	struct List *user_item;


	// Go through users
	user_item = list_pop(&m_users_list);
	while(user_item) {
		struct List *rule_item;
		fr_user_t *user	 = container_of(user_item, fr_user_t, node);

		// All rules for this user
		rule_item = list_pop(&user->rules_list);
	        while(rule_item) {
			fr_rule_t *rule	 = container_of(rule_item, fr_rule_t, node);

			fr_free_rule(rule->code);
			free(rule->str);
			free(rule->dbname);
			free(rule);
			rule_item = list_pop(&user->rules_list);
		}
		free(user->username);
		free(user);
		user_item = list_pop(&m_users_list);
	}
}




/////////////////////////////////////////////////////////////////////////////
// Config file parsing
//



// Skip whitespace including newlines, return false on EOF 
static bool skipws(char **p) {
	   while (**p && isspace(**p)) (*p)++;
	   if (**p == 0)
		   return false;
	   else
		   return true;
}

// Skip spaces and tabs NOT newlines, return false on EOF 
static bool skipblanks(char **p) {
	   while (**p && isblank(**p)) (*p)++;
	   if (**p == 0)
		   return false;
	   else
		   return true;
}


// Remove 'escape' characters and flatten the string out
static void unescape(char *p) {
        char *s = p;
        while (*p) {
                if (*p == '\\') {
			p++;
                }
                *s++ = *p++;
        }
        // terminate actual value 
        *s = 0;
}


// Process a line of X=Y entries, including quoted values and escaped characters 
// Return the username & dbname
// Any other entries are errors (right now)
static bool fr_newrule(char *line, char **username, char **dbname) {
	char *p;
	char *end;
	char *key;
	char *value;
	bool inquotes;
	bool escaped;
	bool error;

	error    = false;
	escaped  = false;
	inquotes = false;

	p = line;
	while (*p) {
	   // Skip white space 
	   if (!skipws(&p))
		break;

	   // Found start of key.... 
	   key=p;
	   while (*p && *p!='=' && !isspace(*p)) p++;
	   if (*p == 0) // EOF?
		break;

	   end=p;
	   if (!skipblanks(&p))
		break;

	   if (*p !='=') {	// Error parsing - expect X = Y 
		log_error("Error parsing fastroutes - missing '=' on rule entry");
		error = true;
		break;
	   }
	   
	   p++;			// Pass over '=' 

	   *end='\0';
	   if (key==end) {	// Zero length key? 
		log_error("Error parsing fastroutes - missing key name");
		error = true;
		break;
	   }

	   // Skip blanks     
	   if (!skipblanks(&p))
		   break;

	   // Start of a quote block?
	   if (*p=='\"') {
		   inquotes = true;
		   p++;
	   }
	   else {
		   inquotes = false;
	   }
	   value = p;
	   end   = NULL;
	   while(*p) {
		   if (escaped) {
			   p++;
			   escaped = false;
			   continue;
		   }

		   if (*p =='\\') {
			   escaped = true;
			   p++;
			   continue;
		   }

		   // If in quotes, end on a '"' otherwise, end on whitespace 
		   if (inquotes) {
			   if (*p=='\"') {
			   	end = p;
				p++;
			   	break;
			   }
		   }
		   else {
			   if (*p=='\"') {	// Unexpected quotes 
		                log_error("Error parsing fastroutes - Unexpected \" character");
		                error = true;
				break;
			   }
			   if (isspace(*p)) {	// End on whitespace...
				end = p;
				p++;
				break;
			   }
		   }
		   p++;
	   }
	   if (!end) { // EOF? 
		   end = p;
	   }
	   
		*end='\0';
		unescape(value);
		log_debug("TAG>>%s<<   VALUE>>%s<<", key, value);
		if (strcmp(key, "username")==0) {
			*username = strdup(value);
			if (!*username) {
				log_error("Error parsing fastroutes - Out of memory");
				error = true;
			        break;
			}
		}
		else if (strcmp(key, "newdbname")==0) {
			*dbname = strdup(value);
			if (!*dbname) {
				log_error("Error parsing fastroutes - Out of memory");
				error = true;
			        break;
			}
		}
		else {
			log_error("Error parsing fastroutes - Unknown key %s", key);
			error = true;
			break;
		}
	   
	}


	if (*username ==NULL) {
		log_error("Error parsing fastroutes - Missing username");
		error = true;
	}
	if (*dbname ==NULL) {
		log_error("Error parsing fastroutes - Missing newdbname");
		error = true;
	}

	if (error) {
		if (*username != NULL) {
			free(*username);
			*username = NULL;
		}
		if (*dbname != NULL) {
			free(*dbname);
			*dbname = NULL;
		}
		return false;
	}

   return true;
}




// Load routing rules from config file.
// Format:  
//
// rule: tag=value	username=<username> newdbname=<newdbname>
// regexes follow, one per line
// Comments start with # or ;
//

static bool fr_loadrules(char *filename) {
	char      *buf;
	char      *p;
	char      *line_start;
	char      *non_white;
	fr_user_t *current_user = NULL;
	fr_rule_t *rule         = NULL;
	char      *dbname       = NULL;
	bool       success      = false;

	// Expected that existing rules have already been deleted before this is called
	//

	buf = load_file(filename, NULL);
	if (buf == NULL) {
		log_error("Unable to load fastroute rules from file %s", filename);
		return false;
	}

	p = buf;
	while (*p) {
		// space at the start of line - including empty lines 
		skipws(&p);

		// skip comment lines 
		if (*p == '#' || *p == ';') {
			while (*p && *p != '\n') p++;
			continue;
		}

		// done? 
		if (*p == 0)
			break;

		// Now at start of text, and not a commented line 
		line_start = p;
		non_white  = p;
		while (*p && *p != '\n') {

			if (isblank(*p))
			{
				skipblanks(&p);
			}
			else {
				p++;
				non_white=p;
			}
		}

		// Remove any trailing white space 
                if (non_white!=p) {
		  *non_white='\0';
		}

		// Position us over the NL char 
                if (*p && *p=='\n') {
		       *p='\0';
                        p++;
                }

		// line_start now points at a NUL terminated, white space trimmed line 

		// Are we starting a new rule set? 
		if (strncmp(line_start, "rule:", 5)==0) {
			char *username = NULL;

			if (dbname != NULL) {
				free(dbname);
				dbname = NULL;
			}
			if (!fr_newrule(line_start+5, &username, &dbname)) {
				log_error("Unable to load new rules");
				goto fr_loadrules_error;
			}

			// No user / Different user?  
			if (current_user == NULL || strcmp(current_user->username, username)) {
				current_user = fr_create_user(username);

				if (!current_user) {
					log_error("Unable to create user !? Likely out of memory");
					free(username);
					free(dbname);
					goto fr_loadrules_error;
				}
			}
			free(username);
			// NB dbname is used later when creating regex rules

		}
		else { // Must be in a rule definition, and this is a regex 
			if (current_user==NULL) {
				log_error("Unable to load fastroute rules - need a rule to be defined before regex lines");
				goto fr_loadrules_error;
			}
			else {
				log_debug("REGEX>>%s<<", line_start);
				pcre2_code *code = fr_compile(line_start);
				if (!code) {
					log_error("Unable to load fastroute rules - Error compiling regex: %s", line_start);
					goto fr_loadrules_error;
				}

				rule = malloc(sizeof(fr_rule_t));
				if (!rule) {
					log_error("Out of memory");
					goto fr_loadrules_error;
				}

				list_init(&rule->node);
				rule->code   = code;
				rule->str    = strdup(line_start);		// FIXME
				rule->dbname = strdup(dbname);
				list_append(&current_user->rules_list, &rule->node);
			}
		}

	}

	// Popped out the end successfully
	success = true;


fr_loadrules_error:
	// Did something go wrong?  Try to cleanup
	if (!success) {
		fr_delete_users();

	}

	if (dbname!= NULL) {
		free(dbname);
	}

	free(buf);
	return success;
}


/////////////////////////////////////////////////////////////////////////////
// The 'business end'
//
//
//



// Initialise this module from cold 
bool fr_initialise(void) {
	list_init(&m_users_list);
	m_initialised = true;
	return true;
}


// For a given user, check this 'sql' against all the loaded rules 
// On match, return the dbname linked to that rule.
static char *fr_check(PgSocket *client, const char *username, const char *sql) {
	fr_user_t *user = NULL;
	struct List *item;
	int res;

	user = fr_get_user(username);

	if (!user) {
		return NULL;
	}

	list_for_each(item, &user->rules_list) {
		fr_rule_t *rule	 = container_of(item, fr_rule_t, node);

                res = fr_trymatch(client, rule->code, sql);

		if (res) {
			char *ret = strdup(rule->dbname);
			if (ret == NULL) {
				slog_error(client, "out of memory....");
				return NULL;
			}

			return ret;
		}
	}
        return NULL;
}

// Entry point to this module, by call from routermodule 
char *fastrouter(PgSocket *client, char *rulesfilename, char *username, char *query) {
	char *dbname = NULL;


	// One off module initialisation 
	if (!m_initialised) {
		if (!fr_initialise()) {
			log_error("Not able to initialise the fastrouter module ?!");
			return NULL;
		}
	}


	// Rules changed?  Delete existing rules, and free filename
	if (m_current_filename !=NULL && strcmp(m_current_filename, rulesfilename)!=0) {
		free(m_current_filename);
		m_current_filename = NULL;

		// Delete those existing rules...
		fr_delete_users();
	}

	// Load the rules?
	if (m_current_filename == NULL) {

		m_current_filename = strdup(rulesfilename);
		if (m_current_filename == NULL) {
			log_error("Out of memory");
			return NULL;
		}
		
		if (!fr_loadrules(m_current_filename)) {
			free(m_current_filename);
			m_current_filename=NULL;
			return NULL;
		}
	}

	
	// Try any user specific rules first 
	dbname = fr_check(client, username, query);
	if (dbname) {
		return dbname;
	}

	// Try wildcard user rules second 
	dbname = fr_check(client, "*", query);
	if (dbname) {
		return dbname;
	}


	// No rules matched, return NULL
	return NULL;
}


