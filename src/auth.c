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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "auth.h"
#include "base64.h"
#include "md5.h"
#include "salsa20-orange.h"
#include "utils.h"



struct safe_string {
   char* data;
   size_t size;
};



#define STR_UNKNOWN_ERROR "unknown error"
#define STR_NO_CODE " (no code"
#define STR_CODE_BEGIN " (code "
#define STR_CODE_END ")"

#define STR_SSO_URI "https://sso.orange.fr/WT/userinfo/"
#define STR_SSO_URI_PART1 "?serv=DC-PCC&wt-email="
#define STR_SSO_URI_PART2 "&wt-pwd="
#define STR_SSO_URI_PART3 "&wt-cvt=4&info=cooses%2Clulo%2Cluip%2Cspr%2Cutz"


static struct step1_result* step1_result_create() {
   struct step1_result* s1r = malloc(sizeof(struct step1_result));
   memset(s1r, 0, sizeof(struct step1_result));
   return s1r;
}

void step1_result_free(struct step1_result* s1r) {
   if (s1r->status != NULL)
      free(s1r->status);
   if (s1r->token != NULL)
      free(s1r->token);
}
   


static struct sip_params* sip_params_create() {
   struct sip_params* s2r = malloc(sizeof(struct sip_params));
   memset(s2r, 0, sizeof(struct sip_params));
   return s2r;
}

void sip_params_free(struct sip_params* s2r) {
   if (s2r->out_proxy != NULL)
      free(s2r->out_proxy);
   if (s2r->ua_domain != NULL)
      free(s2r->ua_domain);
   if (s2r->ndip != NULL)
      free(s2r->ndip);
   if (s2r->impi != NULL)
      free(s2r->impi);
   if (s2r->sip_uri != NULL)
      free(s2r->sip_uri);
   if (s2r->auth_data != NULL)
      free(s2r->auth_data);
   if (s2r->ua_string != NULL)
      free(s2r->ua_string);
}





void dump_sip_params(struct sip_params* p)
{
   if (p == NULL) {
      printf("(null)\n");
      return;
   }


   printf("out_proxy      = %s\n", p->out_proxy);
   printf("out_proxy_port = %s\n", p->out_proxy_port);
   printf("local_port     = %d\n", p->local_port);
   printf("register_delay = %d\n", p->register_delay);
   printf("ua_domain      = %s\n", p->ua_domain);
   printf("ndip           = %s\n", p->ndip);
   printf("impi           = %s\n", p->impi);
   printf("sip_uri        = %s\n", p->sip_uri);
   printf("auth_data      = %s\n", p->auth_data);
   printf("ua_string      = %s\n", p->ua_string);
   printf("ha1            = %s\n", p->ha1);
}





size_t auth_step1_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
   struct safe_string *response = (struct safe_string *) userdata;
   size_t cur_len = strlen(response->data);

   while (response->size < cur_len + size * nmemb + 1) {
      response->data = realloc(response->data, 2 * response->size);
      response->size *= 2;
   }
   memcpy(response->data + cur_len, ptr, size * nmemb);
   cur_len += size * nmemb;
   response->data[cur_len] = '\0';

   return size * nmemb;
}








int auth_step1_parse_result(const char* source, struct step1_result *result)
{
   xmlDoc* doc = NULL;
   xmlNode* node;
   enum { 
      START, 
      WT_RESPONSE_READ, 
      ERROR_READ, 
      IDENTIFIERS_READ 
   } state = START;

   char* x_token  = NULL;
   char* x_code   = NULL;
   char* x_errmsg = NULL;
   char* tmp      = NULL;

   doc = xmlReadMemory(source, strlen(source), "", NULL, XML_PARSE_NONET);
   if (doc == NULL) {
      fprintf(stderr, "could not parse server response\n");
      fprintf(stderr, "server response follows:\n%s\n", source);
      fprintf(stderr, "==CUT==\n");
      return 1;
   }

   for (node = xmlDocGetRootElement(doc); node != NULL; node = node->next) {
loop_restart:
      if (!node)
         break;
      if (node->type != XML_ELEMENT_NODE)
         continue;

      if (state == START
            && !xmlStrcmp(node->name, (const xmlChar*)"WTResponse")) {
         state = WT_RESPONSE_READ;
         node  = node->children;
         goto loop_restart;
      }
      else if (state == WT_RESPONSE_READ
            && !xmlStrcmp(node->name, (const xmlChar*)"error")) {
         state = ERROR_READ;
         node  = node->children;
         goto loop_restart;
      }
      else if (state == WT_RESPONSE_READ
            && !xmlStrcmp(node->name, (const xmlChar*)"identifiers")) {
         state = IDENTIFIERS_READ;
         node  = node->children;
         goto loop_restart;
      }
      else if (state == ERROR_READ) {
         if (!xmlStrcmp(node->name, (const xmlChar*)"code")) 
            x_code   = strdup((char*)node->children->content);
         else if (!xmlStrcmp(node->name, (const xmlChar*)"message"))
            x_errmsg = strdup((char*)node->children->content);
      }
      else if (state == IDENTIFIERS_READ) {
         xmlChar *ident_name, *ident_value;

         if (xmlStrcmp(node->name, (const xmlChar*)"ident"))
            continue;

         ident_name  = xmlGetProp(node, (const xmlChar*)"name");
         ident_value = xmlGetProp(node, (const xmlChar*)"value");

         if (ident_name == NULL || ident_value == NULL)
            continue;
         if (!xmlStrcmp(ident_name, (const xmlChar*)"cooses"))
            x_token = strdup((char*)ident_value);

         xmlFree(ident_name);
      }
   }

   /* if we didn't find a token, there surely must have been an error */
   if (x_token == NULL) {
      size_t len = 0;

      if (x_code != NULL && x_errmsg != NULL)
         len = 1 + strlen(x_code) + strlen(x_errmsg)
                 + strlen(STR_CODE_BEGIN STR_CODE_END);
      else if (x_code == NULL && x_errmsg == NULL)
         len = 1 + strlen(STR_UNKNOWN_ERROR STR_NO_CODE STR_CODE_END);
      else if (x_code != NULL && x_errmsg == NULL) 
         len = 1 + strlen(STR_UNKNOWN_ERROR STR_CODE_BEGIN STR_CODE_END) 
                 + strlen(x_code);
      else if (x_code == NULL && x_errmsg != NULL)
         len = 1 + strlen(x_errmsg) + strlen(STR_NO_CODE STR_CODE_END);
         

      tmp = malloc(len * sizeof(char));
      if (!tmp) { fprintf(stderr, "malloc failed\n"); return 1; }
      
      strcpy(tmp, (x_errmsg != NULL) ? x_errmsg : STR_UNKNOWN_ERROR);
      strcat(tmp, (x_code != NULL) ? STR_CODE_BEGIN : STR_NO_CODE);
      strcat(tmp, (x_code != NULL) ? x_code : "");
      strcat(tmp, STR_CODE_END);


      result->status = tmp;
      result->token  = NULL;
   }
   else {
      result->status = strdup("OK");
      result->token  = x_token;
   }

   /* don't free x_token or tmp because we stuffed them into result */
   if (x_code != NULL)   free(x_code);
   if (x_errmsg != NULL) free(x_errmsg);

   return 0;
}




int auth_step2_parse_result(const char* source, struct sip_params *result)
{
   xmlDoc* doc = NULL;
   xmlNode* cur_node;
   int level = 0;

   doc = xmlReadMemory(source, strlen(source), "", NULL, XML_PARSE_NONET);
   if (doc == NULL) {
      fprintf(stderr, "could not parse server response\n");
      fprintf(stderr, "server response follows:\n%s\n", source);
      fprintf(stderr, "==CUT==\n");
      return 1;
   }


   for (cur_node = xmlDocGetRootElement(doc); cur_node; cur_node = cur_node->next) {
loop_restart:
      if (!cur_node) 
         break;
      if (cur_node->type != XML_ELEMENT_NODE)
         continue;


      /* Root element: descend one level */
      if (level == 0 && !strcmp((char*)cur_node->name, "VoiceService")) {
         level = 1;
         cur_node = cur_node->children;
         goto loop_restart;
      }
      /* VoiceProfile subelement: descend one level too (assuming
       * there is only one VoiceProfile) */
      if (level == 1 && !strcmp((char*)cur_node->name, "VoiceProfile")) {
         level = 2;
         cur_node = cur_node->children;
         goto loop_restart;
      }

      if (level != 2)
         continue;


      /* Parse all remaining interesting XML values */
      if (!strcmp((char*)cur_node->name, "OutboundProxy"))
         result->out_proxy    = strdup((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "OutboundProxyPortNumber"))
         result->out_proxy_port = strdup((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "LocalPortNumber"))
         result->local_port   = atoi((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "RegistrationDelay"))
         result->register_delay  = atoi((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "UserAgentDomain"))
         result->ua_domain    = strdup((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "NDIP"))
         result->ndip      = strdup((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "IMPI"))
         result->impi      = strdup((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "URISIP"))
         result->sip_uri      = strdup((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "AuthentData"))
         result->auth_data = strdup((char*)cur_node->children->content);
      else if (!strcmp((char*)cur_node->name, "SiPUserAgent")) /* not a typo */
         result->ua_string = strdup((char*)cur_node->children->content);
      
   }

   xmlFreeDoc(doc);
   return 0;
}





struct step1_result* auth_step1(CURL* curl, char* user, char* password)
{
   char* auth_uri;
   char *uenc_user, *uenc_pass;

   struct safe_string response;
   struct step1_result* result;

   int ret;

   size_t uenc_user_len = urlencode(NULL, user);
   size_t uenc_pass_len = urlencode(NULL, password);
   size_t auth_uri_len = strlen(STR_SSO_URI STR_SSO_URI_PART1 STR_SSO_URI_PART2
         STR_SSO_URI_PART3) + uenc_user_len + uenc_pass_len + 1;

   response.data = malloc(1000 * sizeof(char));
   response.size = 1000;
   memset(response.data, 0, 1000);

   auth_uri = malloc(auth_uri_len * sizeof(char));

   uenc_user = malloc((uenc_user_len + 1) * sizeof(char));
   uenc_pass = malloc((uenc_pass_len + 1) * sizeof(char));
   urlencode(uenc_user, user);
   urlencode(uenc_pass, password);

   strcpy(auth_uri, STR_SSO_URI STR_SSO_URI_PART1);
   strcat(auth_uri, uenc_user);
   strcat(auth_uri, STR_SSO_URI_PART2);
   strcat(auth_uri, uenc_pass);
   strcat(auth_uri, STR_SSO_URI_PART3);

   curl_easy_setopt(curl, CURLOPT_URL, auth_uri);
   curl_easy_setopt(curl, CURLOPT_USERAGENT, "");
   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, auth_step1_write_callback);
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

   if ((ret = curl_easy_perform(curl))) {
      fprintf(stderr, "auth_step1: %s\n", curl_easy_strerror(ret));
      exit(1);
   }

   result = step1_result_create();
   auth_step1_parse_result(response.data, result);

   free(uenc_user);
   free(uenc_pass);
   free(auth_uri);

   free(response.data);

   return result;
}




int auth_step2(CURL* curl, struct step1_result* s1r, 
      struct sip_params** p_s2r)
{
   char* postdata;
   char curl_errbuf[CURL_ERROR_SIZE] = "";
   size_t content_length;

   int ret, result = 0;

   struct safe_string response;
   struct sip_params* s2r;

   const char fake_os_name[] = "Android";
   const char fake_os_ver[]  = "5.0";
   const char fake_ua_ver[]  = "2.6.0";
   const char fake_lang[]    = "fr";
   const char fake_mode[]    = "Nominal";

   if (s1r == NULL)
      return 1;
   if (strcmp(s1r->status, "OK"))
      return 1;

   response.data = malloc(1000 * sizeof(char));
   if (response.data == NULL)
      return 1;
   response.size = 1000;
   memset(response.data, 0, 1000);

   content_length = strlen("cookie=&version=&OSName=&OSVersion=&language=&mode=") 
      + strlen(fake_os_name)
      + strlen(fake_os_ver)
      + strlen(fake_ua_ver)
      + strlen(fake_lang)
      + strlen(fake_mode)
      + strlen(s1r->token);

   postdata = malloc((content_length + 1) * sizeof(char));
   if (postdata == NULL) {
      result = 1;
      goto err_1;
   }
   memset(postdata, 0, (content_length + 1) * sizeof(char));
   strcpy(postdata, "cookie=");
   strcat(postdata, s1r->token);
   strcat(postdata, "&version=");
   strcat(postdata, fake_ua_ver);
   strcat(postdata, "&OSName=");
   strcat(postdata, fake_os_name);
   strcat(postdata, "&OSVersion=");
   strcat(postdata, fake_os_ver);
   strcat(postdata, "&language=");
   strcat(postdata, fake_lang);
   strcat(postdata, "&mode=");
   strcat(postdata, fake_mode);

   
   curl_easy_setopt(curl, CURLOPT_URL,
         "https://sfcpesoft.orange.fr:443/fcpesoft/v2/getTerminalParameters");
   curl_easy_setopt(curl, CURLOPT_POST, 1);
   curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
   curl_easy_setopt(curl, CURLOPT_USERAGENT, "");
   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, auth_step1_write_callback);
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
   curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
   curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);

   if ((ret = curl_easy_perform(curl))) {
      fprintf(stderr, "auth_step2: %s\n", curl_errbuf);
      result = 1;
      goto err_2;
   }

   *p_s2r = sip_params_create();
   s2r = *p_s2r;

   if (s2r == NULL) {
      fprintf(stderr, "sip_params_create() failed\n");
      result = 1;
      goto err_2;
   }

   if (auth_step2_parse_result(response.data, s2r) != 0) {
      result = 1;
      goto err_2;
   }
   compute_digest_ha1(s2r);

err_2:
   free(postdata);
err_1:
   free(response.data);
   
   return result;
}




void compute_digest_ha1(struct sip_params* s2r) 
{
   char* auth_data_dec;
   uint8_t* token;
   uint16_t* scratch;
   size_t scratch_size;
   int i;

   auth_data_dec = malloc(strlen(s2r->auth_data) * sizeof(char));

   /* decode AuthentData */
   base64_decode(s2r->auth_data, auth_data_dec, strlen(s2r->auth_data));

   /* compute scratch size */
   scratch_size = (auth_data_dec[0] * 16);

   /* compute hash on interesting bits of AuthentData */
   token   = malloc(32 * sizeof(uint8_t));
   scratch = malloc(scratch_size * sizeof(uint8_t));
   memcpy(token,   auth_data_dec + scratch_size + 1, 32);
   memcpy(scratch, auth_data_dec + 1, scratch_size);
   free(auth_data_dec);
   
   salsa20_enc(1, scratch, token);

   /* write the result into s2r->ha1 */
   for (i = 0; i < 16; i++)
      sprintf(s2r->ha1 + 2*i, "%02hhx", (unsigned char)(token[i]));

   free(token);
}
