/*
 * Copyright (C) 2014 x0r <x0r@x0r.fr>
 *
 * This file is part of siproxd_orange.
 *
 * siproxd_orange is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * siproxd_orange is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warrantry of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with siproxd_orange; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

/* must be defined before including <plugin.h> */
#define PLUGIN_NAME  plugin_orange

#include "config.h"

#include <assert.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <osipparser2/osip_parser.h>

#include "siproxd.h"
#include "plugins.h"
#include "log.h"

#include "auth.h"
#include "md5.h"
#include "plugin_orange.h"



/* Plug-in identification */
static char name[]="plugin_orange";
static char desc[]="SIP plugin for Orange Livephone, version " PACKAGE_VERSION;

/* global configuration storage - required for config file location */
extern struct siproxd_config configuration;

/* plugin configuration storage */
static struct plugin_config {
   char *username;
   char *password;
   int   force_max_expiry_time;
} plugin_cfg;

/* SIP parameters storage */
static struct sip_params* params;

/* Instructions for config parser */
static cfgopts_t plugin_cfg_opts[] = {
   { "plugin_orange_username",
      TYP_STRING, &plugin_cfg.username,            {0, NULL} },
   { "plugin_orange_password",
      TYP_STRING, &plugin_cfg.password,            {0, NULL} },
   { "plugin_orange_force_max_expiry_time", 
      TYP_INT4, &plugin_cfg.force_max_expiry_time, {0, NULL} },
   {0, 0, 0}
};

/* Forward declaration of private functions */
static int plugin_orange_do_login(struct plugin_config cfg);
static int plugin_orange_determine_target(sip_ticket_t *ticket);
static int plugin_orange_post_proxy(sip_ticket_t *ticket);
static int plugin_orange_process_raw(sip_ticket_t *ticket);
static int plugin_orange_rewrite_authorization(osip_authorization_t *auth, char *method);
static int plugin_orange_patch_message(char* msg);

/* 
 * Initialization.
 * Called once suring siproxd startup.
 */
int  PLUGIN_INIT(plugin_def_t *plugin_def) {
   struct in_addr addr;

   /* API version number of siproxd that this plugin is built against.
    * This constant will change whenever changes to the API are made
    * that require adaptions in the plugin. */
   plugin_def->api_version=SIPROXD_API_VERSION;

   /* Name and descriptive text of the plugin */
   plugin_def->name=name;
   plugin_def->desc=desc;

   /* Execution mask - during what stages of SIP processing shall
    * the plugin be called. */
   plugin_def->exe_mask=PLUGIN_PROCESS_RAW
                      | PLUGIN_DETERMINE_TARGET 
                      | PLUGIN_PRE_PROXY 
                      | PLUGIN_POST_PROXY;

   /* read the config file */
   if (read_config(configuration.configfile,
                   configuration.config_search,
                   plugin_cfg_opts, name) == STS_FAILURE) {
      ERROR("Plugin '%s': could not load config file", name);
      return STS_FAILURE;
   }

   /* check config consistency */
   if (plugin_cfg.username == NULL
         || strlen(plugin_cfg.username) == 0) {
      ERROR("%s_username not set, please set it", name);
      return STS_FAILURE;
   }
   if (plugin_cfg.password == NULL
         || strlen(plugin_cfg.password) == 0) {
      ERROR("%s_password not set, please set it", name);
      return STS_FAILURE;
   }

   if (plugin_cfg.force_max_expiry_time > 3600) {
      WARN("capping plugin_orange_force_max_expiry_time at 3600 seconds");
      plugin_cfg.force_max_expiry_time = 3600;
   }

   /* connect to Orange auth server */
   INFO("logging in");

   if (plugin_orange_do_login(plugin_cfg) == STS_FAILURE)
   {
      ERROR("%s: could not login to account", name);
      return STS_FAILURE;
   }


   /* make sure we can resolve subsequent names */
   if (get_ip_by_host(params->out_proxy, &addr) == STS_FAILURE)
   {
      ERROR("unable to resolve %s; make sure you are using "
            "Orange's DNS servers - this plugin will NOT work "
       "otherwise!", params->out_proxy);
      sip_params_free(params);
      return STS_FAILURE;
   }
   


   INFO("%s is initialized", name);
   return STS_SUCCESS;
}

/*
 * Processing.
 */
int  PLUGIN_PROCESS(int stage, sip_ticket_t *ticket){

   switch(stage) {
      case PLUGIN_PROCESS_RAW:
         return plugin_orange_process_raw(ticket);
      case PLUGIN_DETERMINE_TARGET:
         return plugin_orange_determine_target(ticket);
      case PLUGIN_POST_PROXY:
         return plugin_orange_post_proxy(ticket);
      default:
         break;
   }

   return STS_SUCCESS;
}

/*
 * De-Initialization.
 * Called during shutdown of siproxd. Gives the plugin the chance
 * to clean up its mess (e.g. dynamic memory allocation, database
 * connections, whatever the plugin messes around with)
 */
int  PLUGIN_END(plugin_def_t *plugin_def){
   INFO("plugin_orange ends here");
   return STS_SUCCESS;
}



/*
 * Private functions
 */



static int plugin_orange_do_login(struct plugin_config cfg)
{
   int ret;
   int result = STS_SUCCESS;
   CURL *curl;
   struct step1_result* s1r; 

   /* Init libxml2 + check version ABI */
   LIBXML_TEST_VERSION

   /* Init libcurl */
   if ((ret = curl_global_init(CURL_GLOBAL_ALL))) {
      ERROR("%s: could not initialize libcurl", name);
      result = STS_FAILURE;
      goto err_1;
   }

   curl = curl_easy_init();
   if (curl == NULL) {
      ERROR("%s: curl_easy_init() failed", name);
      result = STS_FAILURE;
      goto err_1;
   }

   /* Identification */
   s1r = auth_step1(curl, cfg.username, cfg.password);

   if (strcmp(s1r->status, "OK")) {
      ERROR("authentication status %s; wrong credentials?", s1r->status);
      result = STS_FAILURE;
      goto err_2;
   }

   
   /* Récupération des paramètres SIP */
   ret = auth_step2(curl, s1r, &params);
   if (ret != 0) {
      ERROR("auth_step2 failed, aborting");
      result = STS_FAILURE;
      goto err_2;
   }


   DEBUGC(DBCLASS_PLUGIN, "obtained from SIP server: ");
   DEBUGC(DBCLASS_PLUGIN, "outbound_domain_name = %s", params->ua_domain);
   DEBUGC(DBCLASS_PLUGIN, "outbound_domain_host = %s", params->out_proxy);
   DEBUGC(DBCLASS_PLUGIN, "outbound_domain_port = %s", params->out_proxy_port);

   DEBUGC(DBCLASS_PLUGIN, "ha1: %s", params->ha1);

   /* Nettoyage */
err_2:
   step1_result_free(s1r);
   curl_easy_cleanup(curl);
err_1:
   xmlCleanupParser();

   return result;

}


static int plugin_orange_determine_target(sip_ticket_t *ticket)
{
   osip_authorization_t* auth = NULL;

   /* Don't touch anything that doesn't involve us */
   if (!MSG_IS_REQUEST(ticket->sipmsg))
      return STS_SUCCESS;
   if (strcmp(ticket->sipmsg->req_uri->host, "orange-multimedia.fr"))
      return STS_SUCCESS;

   /* Deny REGISTER if username part doesn't match what we want */
   if (MSG_IS_REGISTER(ticket->sipmsg) 
            && strcmp(ticket->sipmsg->from->url->username, params->ndip))
   {
      ERROR("received %s for wrong username %s (expected NDIP: %s)",
            ticket->sipmsg->sip_method,
            ticket->sipmsg->from->url->username,
            params->ndip);
      sip_gen_response(ticket, 403 /* Forbidden */);
      return STS_SIP_SENT;
   }

   /* change REGISTER url if it's equal to orange-multimedia.fr;
    * we need this so that siproxd opens a socket to the outbound proxy. */
   DEBUGC(DBCLASS_PLUGIN, "%s: setting URL host to %s:%s", 
         ticket->sipmsg->sip_method, 
         params->out_proxy, 
         params->out_proxy_port);
   osip_uri_set_host(ticket->sipmsg->req_uri, strdup(params->out_proxy));
   osip_uri_set_port(ticket->sipmsg->req_uri, strdup(params->out_proxy_port));
   
   /* try to grab an Authorization or a Proxy-Authorization header; if there
    * isn't, we're done */
   if (osip_list_size(&ticket->sipmsg->authorizations)) {
      auth = osip_list_get(&ticket->sipmsg->authorizations, 0);
   }
   else if (osip_list_size(&ticket->sipmsg->proxy_authorizations)) {
      auth = osip_list_get(&ticket->sipmsg->proxy_authorizations, 0);
   }

   if (auth == NULL) {
      INFO("proxying REGISTER without {Proxy-,}Authorization: headers");
      return STS_SUCCESS;
   }
   else {
      if (!osip_authorization_get_response(auth))
      {
         DEBUGC(DBCLASS_PLUGIN, "Authorization header but no response?!");
         return STS_SUCCESS;
      }

      INFO("rewriting {Proxy-,}Authorization: headers");
      plugin_orange_rewrite_authorization(auth, osip_message_get_method(ticket->sipmsg));
   }



   return STS_SUCCESS;
}







static int plugin_orange_rewrite_authorization(osip_authorization_t *auth, char *method)
{
   char* scratch;

   /* rewrite Authorization uri if registering */
   if (! strcmp(method, "REGISTER")) {
      scratch = malloc((
               3 + strlen("sip::")
               + strlen(params->ua_domain)
               + strlen(params->out_proxy_port)) * sizeof(char));
      sprintf(scratch, "\"sip:%s:%s\"", params->ua_domain, params->out_proxy_port);
      osip_authorization_set_uri(auth, scratch);
   }

   /* rewrite Authorization username */
   scratch = malloc(3 + strlen(params->impi));
   sprintf(scratch, "\"%s\"", params->impi);
   osip_authorization_set_username(auth, scratch);

   /* rewrite Authorization response */
   {
      char* nonce;
      char* cnonce;
      char* request_uri;
      char response[35];

      /* make sure we aren't going to do funky things with NULL pointers */
      if (osip_authorization_get_nonce(auth) == NULL) {
         ERROR("Authorization header contains no nonce");
         return STS_FAILURE;
      }
      if (osip_authorization_get_cnonce(auth) == NULL) {
         ERROR("Authorization header contains no cnonce");
         return STS_FAILURE;
      }

      
      nonce  = strdup(osip_authorization_get_nonce(auth) + 1);
      cnonce = strdup(osip_authorization_get_cnonce(auth) + 1);
      nonce[strlen(nonce) - 1] = '\0';
      cnonce[strlen(cnonce) - 1] = '\0';

      DEBUGC(DBCLASS_PLUGIN, "ha1      = [%s]", params->ha1);
      DEBUGC(DBCLASS_PLUGIN, "nonce    = [%s]", nonce);
      DEBUGC(DBCLASS_PLUGIN, "nc       = [%s]", osip_authorization_get_nonce_count(auth));
      DEBUGC(DBCLASS_PLUGIN, "cnonce   = [%s]", cnonce);
      DEBUGC(DBCLASS_PLUGIN, "qop      = [%s]", osip_authorization_get_message_qop(auth));

      request_uri = strdup(osip_authorization_get_uri(auth) + 1);
      request_uri[strlen(request_uri) - 1] = '\0';

      compute_digest_response((unsigned char*) params->ha1,
            nonce,
            osip_authorization_get_nonce_count(auth),
            cnonce,
            osip_authorization_get_message_qop(auth),
            method,
            request_uri,
            (unsigned char*) "",
            (unsigned char*) response + 1);
      response[0] = '"';
      response[33] = '"';
      response[34] = '\0';
      osip_authorization_set_response(auth, strdup(response));

      DEBUGC(DBCLASS_PLUGIN, "req_uri  = [%s]", request_uri);
      DEBUGC(DBCLASS_PLUGIN, "response = [%s]", response);

      free(request_uri);
   }



   return STS_SUCCESS;
}



static int plugin_orange_process_raw(sip_ticket_t *ticket)
{
   /* The idea here is to find out whether this is a SIP message that interests
    * this plugin (contains a orange-multimedia.fr URL, or if not, contains our
    * full phone number).  If so, rewrite the "tel:" To: URIs so that libosip2
    * likes them better. */

   char* tel_uri;

   if (strstr(ticket->raw_buffer, "@orange-multimedia.fr") == NULL) {
      if (strstr(ticket->raw_buffer, params->ndip) == NULL) {
         DEBUGC(DBCLASS_PLUGIN, "raw message probably not intended for us, "
               "leaving it untouched");
         return STS_SUCCESS;
      }
   }

   /* is it for us? check if there's a <tel:(our number)> in the packet */
   tel_uri = strstr(ticket->raw_buffer, "<tel:");
   if (tel_uri == NULL)
      return STS_SUCCESS;
   if (strncmp(tel_uri + 5, params->ndip, strlen(params->ndip)))
      return STS_SUCCESS;

   plugin_orange_patch_message(ticket->raw_buffer);
   ticket->raw_buffer_len = strlen(ticket->raw_buffer);

   DEBUGC(DBCLASS_PLUGIN, "substituted tel: URI with \"sip:\"");


   return STS_SUCCESS;
}





static int plugin_orange_post_proxy_requests(sip_ticket_t *ticket)
{
   if (!strcmp(ticket->sipmsg->req_uri->host, params->out_proxy)) {
      osip_uri_set_host(ticket->sipmsg->req_uri, strdup(params->ua_domain));
   }

   /* remove stupid Cisco stuff from Contact: header*/
   {
      osip_contact_t *ct, *ct2;
      osip_uri_t *c_uri;
      osip_generic_param_t *p;
      char *str;
      int i;
      

      osip_message_get_contact(ticket->sipmsg, 0, &ct);
      if (ct != NULL) {

         osip_contact_init(&ct2);
         osip_uri_clone(osip_contact_get_url(ct), &c_uri);
         osip_contact_set_url(ct2, c_uri);

         for (i = 0; ; i++) {
            osip_contact_param_get(ct, i, &p);
            if (p == NULL)
               break;
            if (!strcmp(p->gname, "+sip.instance"))
               continue;
            if (!strcmp(p->gname, "+u.sip!model.ccm.cisco.com"))
               continue;

            osip_contact_param_add(ct2, strdup(p->gname), strdup(p->gvalue));
         }

         osip_list_remove(&ticket->sipmsg->contacts, 0);
         osip_contact_to_str(ct2, &str);
         osip_message_set_contact(ticket->sipmsg, str);
      }

   }

   return STS_SUCCESS;
}





static void plugin_orange_set_contact_expiry(sip_ticket_t *ticket, int value)
{
   char value_str[6];
   osip_contact_t *contact, *ct2;
   osip_uri_t *c_uri;
   osip_generic_param_t *p;
   char *str;
   int num_contacts, i, j;

   /* sanitize value */
   value = (value > 3600) ? 3600 : value;
   sprintf(value_str, "%d", value);


   /* iterate over each Contact header in message */
   num_contacts = osip_list_size(&ticket->sipmsg->contacts);

   for (i = 0; i < num_contacts; i++) {
      osip_message_get_contact(ticket->sipmsg, i, &contact);
      assert(contact != NULL);
      
      osip_contact_init(&ct2);
      osip_uri_clone(osip_contact_get_url(contact), &c_uri);
      osip_contact_set_url(ct2, c_uri);

      for (j = 0; ; j++) {
         osip_contact_param_get(contact, j, &p);
         if (p == NULL)
            break;

         if (!strcmp(p->gname, "expires"))
            osip_contact_param_add(ct2, strdup(p->gname), strdup(value_str));
         else
            osip_contact_param_add(ct2, strdup(p->gname), strdup(p->gvalue));
      }

      osip_contact_to_str(ct2, &str);
      osip_message_set_contact(ticket->sipmsg, str);
   }

   for (j = 0; j < num_contacts; j++) {
      osip_list_remove(&ticket->sipmsg->contacts, 0);
   }
}





static int plugin_orange_post_proxy_responses(sip_ticket_t *ticket)
{
   /* find response for REGISTER dialogs (using CSeq) */
   {
      osip_cseq_t* cseq = osip_message_get_cseq(ticket->sipmsg);
      if (cseq == NULL)
         return STS_SUCCESS;

      if (strcmp(cseq->method, "REGISTER"))
         return STS_SUCCESS;

      DEBUGC(DBCLASS_PLUGIN, "found response for REGISTER dialog");
   }

   /* fix Contact: headers */
   {
      int min_expires = -1;
      int i, j;
      osip_contact_t* contact;

      /* if we are forcing a minimum expiry time, use it here too */
      if (plugin_cfg.force_max_expiry_time > 0) {
         DEBUGC(DBCLASS_PLUGIN, "forcing minimum expiry time to %d", 
               plugin_cfg.force_max_expiry_time);
         min_expires = plugin_cfg.force_max_expiry_time;
      }

      /* iterate over each Contact header in message */
      for (i = 0; ; i++)
      {
         osip_message_get_contact(ticket->sipmsg, i, &contact);
         if (contact == NULL)
            break;
   
         /* iterate over each contact parameter */
         for (j = 0; ; j++)
         {
            osip_generic_param_t *p;
            osip_contact_param_get(contact, j, &p);
            if (p == NULL)
               break;

            /* if we match an "expires=" Contact parameter, extract its value
             * and determine if it's the smallest so far */
            if (!strcmp(p->gname, "expires")) {
               char* endptr;
               int val = strtol(p->gvalue, &endptr, 10);

               if (*endptr != '\0')
                  continue;

               DEBUGC(DBCLASS_PLUGIN, "found Contact: header with expires=%d", val);

               if (val < min_expires || min_expires == -1)
                  min_expires = val;
            }
         }
      }

      /* force ridiculously short expiry times to 60 seconds (some PBXes really
       * don't like such short values otherwise), but don't touch if expires=0
       * since this means a mapping is being removed */
      if (min_expires > 0 && min_expires < 60) {
         DEBUGC(DBCLASS_PLUGIN, "forcing expires=60");
         min_expires = 60;
      }

      if (min_expires == -1)
         DEBUGC(DBCLASS_PLUGIN, "no Contact header with expiry info found");
      else if (min_expires == 0)
         DEBUGC(DBCLASS_PLUGIN, "found expires=0, not rewriting");
      else {
         /* filter silly values */
         min_expires = (min_expires < 0) ? 3600 : min_expires;

         DEBUGC(DBCLASS_PLUGIN, "minimum expiry time is %d s", min_expires);
         plugin_orange_set_contact_expiry(ticket, min_expires);
      }
   }


   return STS_SUCCESS;
}




static int plugin_orange_post_proxy(sip_ticket_t *ticket)
{
   if (MSG_IS_REQUEST(ticket->sipmsg))
      return plugin_orange_post_proxy_requests(ticket);
   else if (MSG_IS_RESPONSE(ticket->sipmsg))
      return plugin_orange_post_proxy_responses(ticket);

   return STS_SUCCESS;
}




static int plugin_orange_patch_message(char* msg)
{
   char *msg_cur, *new_cur;
   char new[BUFFER_SIZE] = { '\0' };

   int  i, state;

   msg_cur = msg;
   new_cur = new;

   state = 0;
   for (i = 0; i < BUFFER_SIZE - 1 && *msg_cur; i++)
   {
      if (state == 0 && !strncmp(msg_cur, "<tel:", 5)) {
         state = 1;
         strncpy(new_cur, "<sip:", BUFFER_SIZE - 1 - i);

         i += 4;
         msg_cur += 5;
         new_cur += 5;
      }
      else if (state == 1 && *msg_cur == '>') {
         state = 0;
         strncpy(new_cur, "@orange-multimedia.fr", BUFFER_SIZE - 1 - i);

         i += 20;
         new_cur += 21;
      }
      else {
         *new_cur++ = *msg_cur++;
      }
   }

   memcpy(msg, new, BUFFER_SIZE);

   return STS_SUCCESS;
}
