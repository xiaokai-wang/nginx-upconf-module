/*
 * Copyright (C) 2015 Weibo Group Holding Limited
 * Copyright (C) 2015 Xiaokai Wang (xiaokai.wang@live.com)
 */


#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>


typedef struct {
    ngx_str_t            method;
    ngx_str_t            ip_port;
    ngx_str_t            upstream;

    time_t               fail_timeout;
    ngx_int_t            weight;
    ngx_uint_t           max_fails;

    unsigned             down:1;
    unsigned             backup:1;
} ngx_http_server_t;


typedef struct {
    ngx_str_t            upconf_dump_path;

    ngx_uint_t           upstream_conf;
} ngx_http_upconf_loc_conf_t;


#if (NGX_HTTP_UPSTREAM_CHECK)

extern ngx_uint_t ngx_http_upstream_check_add_dynamic_peer(ngx_pool_t *pool,
    ngx_http_upstream_srv_conf_t *us, ngx_addr_t *peer_addr);
extern void ngx_http_upstream_check_delete_dynamic_peer(ngx_str_t *name,
    ngx_addr_t *peer_addr);

#endif


static char *ngx_http_upconf_set(ngx_conf_t *cf, ngx_command_t *cmd, 
    void *conf);
static ngx_int_t ngx_http_upconf_handler(ngx_http_request_t *r);
static void ngx_http_upconf_init(ngx_http_request_t *r);
static ngx_int_t ngx_http_upconf_parse_args(ngx_http_request_t *r, 
    ngx_http_server_t *server);
static ngx_int_t ngx_http_upconf_add_peer(ngx_http_request_t *r, 
    ngx_http_server_t *server);
static ngx_int_t ngx_http_upconf_update_peer(ngx_http_request_t *r, 
    ngx_http_server_t *server);
static ngx_int_t ngx_http_upconf_remove_peer(ngx_http_request_t *r, 
    ngx_http_server_t *server)

static ngx_int_t ngx_http_upconf_check_server(
    ngx_http_upstream_srv_conf_t *uscf, ngx_str_t *ip_port);
static void *ngx_http_upconf_lookup_upstream(ngx_str_t *upstream_name);
static void *ngx_http_upconf_server(ngx_http_request_t *r, 
    ngx_http_server_t *server);

static void *ngx_http_upconf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upconf_merge_loc_conf(ngx_conf_t *cf, void *parent, 
    void *child)

static ngx_int_t ngx_http_upconf_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_upconf_init_peers(ngx_cycle_t *cycle, 
    ngx_http_upstream_srv_conf_t *uscf);
static ngx_int_t ngx_http_upconf_parse_dump_file(
    ngx_http_upstream_srv_conf_t *uscf, u_char * server_file);

void ngx_http_upconf_finalize_request(ngx_http_request_t *r);


static ngx_command_t  ngx_http_upconf_commands[] = {

    { ngx_string("upstream_conf"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_upconf_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upconf_loc_conf_t, upstream_conf),
      NULL },

    { ngx_string("upconf_dump_path"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upconf_loc_conf_t, upconf_dump_path),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upconf_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_upconf_create_loc_conf,        /* create location configuration */
    ngx_http_upconf_merge_loc_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_upconf_module = {
    NGX_MODULE_V1,
    &ngx_http_upconf_module_ctx,            /* module context */
    ngx_http_upconf_commands,               /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_http_upconf_init_process,           /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_upconf_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *ret;

    ngx_http_core_loc_conf_t               *clcf;
    ngx_http_upconf_loc_conf_t             *uclcf = conf;

    ret = ngx_conf_set_flag_slot(cf, cmd, conf);
    if(ret != NGX_CONF_OK) {
        return ret;
    }

    if(uclcf->upstream_conf){
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        clcf->handler = ngx_http_upconf_handler;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upconf_handler(ngx_http_request_t *r)
{
    ngx_int_t       rc;

    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_upconf_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_upconf_init(ngx_http_request_t *r)
{
    ngx_http_server_t                  server;

    if (ngx_http_upconf_parse_args(r, &server) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERROR, r->connection->log, 0,
                      "upconf_init: args invalid \"%V\"", &r->args);

        ngx_http_upconf_finalize_request(r, NGX_ERROR);

        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upconf_init: parse args succeed");

    if (ngx_strncmp(server.method.data, "add", server.method.len) == 0){
        if (ngx_http_upconf_add_peer((ngx_cycle_t *)ngx_cycle, 
                                     &server) != NGX_OK) 
        {

            ngx_http_upconf_finalize_request(r, NGX_ERROR);

            return;
        }

    } else if (ngx_strncmp(server.method.data, "remove", server.method.len) == 0){
        if (ngx_http_upconf_remove_peer((ngx_cycle_t *)ngx_cycle, 
                                        &server) != NGX_OK) 
        {

            ngx_http_upconf_finalize_request(r, NGX_ERROR);

            return;
        }

    } else if (ngx_strncmp(server.method.data, "update", server.method.len) == 0){
        if (ngx_http_upconf_update_peer((ngx_cycle_t *)ngx_cycle, 
                                        &server) != NGX_OK) 
        {

            ngx_http_upconf_finalize_request(r, NGX_ERROR);

            return;
        }

    } else if (server.upstream.data != NULL && server.upstream.len != 0) {

        ngx_http_upconf_upstream_show(&server.upstream);

        return;

    } else {

        ngx_http_upconf_finalize_request(r, NGX_ERROR);

        return;
    }

    ngx_http_upconf_finalize_request(r, NGX_OK);
    return;
}


static ngx_int_t
ngx_http_upconf_parse_args(ngx_http_request_t *r, ngx_http_server_t *server)
{
    u_char         *args_p, *args_n, *args_end;
    ngx_int_t       weight, max_fails, fail_timeout, down, backup;

    ngx_str_null(server->method);
    ngx_str_null(server->ip_port);
    ngx_str_null(server->upstream);

    server->weight = 1;
    server->max_fails = 2;
    server->fail_timeout = 10;

    server->down = 0;
    server->backup = 0;

    args_p = r->args.data;
    args_end = r->args.data + r->args.len;
    while (args_p != NULL) {

        if (*args_p == '&') {
            args_n = args_p + 1;

        } else {
            args_n = args_p;
        }

        if (ngx_strncmp(args_n, "add=", 4) == 0) {

            server->method.len = 3;
            server->method.data = ngx_pcalloc(r->pool, 4);
            if (server->method.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                              "upconf_parse_args: memory alloc error");
                return NGX_ERROR;
            }
            ngx_memmove(server->method.data, "add", 3);

            args_p = ngx_strchr((char *)args_n, '&');

            continue;
        }

        if (ngx_strncmp(args_n, "remove=", 7) == 0) {

            server->method.len = 6;
            server->method.data = ngx_pcalloc(r->pool, 7);
            if (server->method.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                              "upconf_parse_args: memory alloc error");
                return NGX_ERROR;
            }
            ngx_memmove(server->method.data, "remove", 6);
 
            args_p = ngx_strchr((char *)args_n, '&');

            continue;
        }

        if (ngx_strncmp(args_n, "update=", 7) == 0) {

            server->method.len = 6;
            server->method.data = ngx_pcalloc(r->pool, 7);
            if (server->method.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                              "upconf_parse_args: memory alloc error");
                return NGX_ERROR;
            }
            ngx_memmove(server->method.data, "update", 6);
 
            args_p = ngx_strchr((char *)args_n, '&');

            continue;
        }

        if (ngx_strncmp(args_n, "upstream=", 9) == 0) {
 
            args_p = ngx_strchr((char *)args_n, '&');
            if (args_p != NULL) {
                server->upstream.len = args_p - args_n + 9;

            } else {
                server->upstream.len = args_end - args_n + 9;
            }

            server->upstream.data = ngx_pcalloc(r->pool, server->upstream.len);
            if (server->upstream.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                              "upconf_parse_args: memory alloc error");
                return NGX_ERROR;
            }
            ngx_memmove(server->upstream.data, args_n + 9, server->upstream.len);

            continue;
        }

        if (ngx_strncmp(args_n, "server=", 7) == 0) {
 
            args_p = ngx_strchr((char *)args_n, '&');
            if (args_p != NULL) {
                server->ip_port.len = args_p - args_n + 7;

            } else {
                server->ip_port.len = args_end - args_n + 7;
            }

            server->ip_port.data = ngx_pcalloc(r->pool, server->ip_port.len);
            if (server->ip_port.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                              "upconf_parse_args: memory alloc error");
                return NGX_ERROR;
            }
            ngx_memmove(server->ip_port.data, args_n + 7, server->ip_port.len);

            continue;
        }

        if (ngx_strncmp(args_n, "weight=", 7) == 0) {

            args_p = ngx_strchr((char *)args_n, '&');
            if (args_p != NULL) {
                weight = ngx_atoi(args_n + 7, args_p - args_n + 7);

            } else {
                weight = ngx_atoi(args_n + 7, args_end - args_n + 7);
            }

            if (weight >= 1) {
                server->weight = weight;

            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upconf_parse_args: invalid weight \"%V\"", 
                              &r->args);
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(args_n, "max_fails=", 10) == 0) {

            args_p = ngx_strchr((char *)args_n, '&');
            if (args_p != NULL) {
                max_fails = ngx_atoi(args_n + 10, args_p - args_n + 10);

            } else {
                max_fails = ngx_atoi(args_n + 10, args_end - args_n + 10);
            }

            if (max_fails >= 0) {
                server->max_fails = max_fails;

            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upconf_parse_args: invalid max_fails \"%V\"", 
                              &r->args);
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(args_n, "fail_timeout=", 13) == 0) {

            args_p = ngx_strchr((char *)args_n, '&');
            if (args_p != NULL) {
                fail_timeout = ngx_atoi(args_n + 13, args_p - args_n + 13);
            } else {
                fail_timeout = ngx_atoi(args_n + 13, args_end - args_n + 13);
            }

            if (fail_timeout >= 0) {
                server->fail_timeout = fail_timeout;

            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upconf_parse_args: invalid fail_timeout \"%V\"", 
                              &r->args);
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(args_n, "down=", 5) == 0) {

            args_p = ngx_strchr((char *)args_n, '&');
            if (args_p != NULL) {
                down = ngx_atoi(args_n + 5, args_p - args_n + 5);
            } else {
                down = ngx_atoi(args_n + 5, args_end - args_n + 5);
            }

            if (down != 0 && down != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upconf_parse_args: invalid down \"%V\"", 
                              &r->args);
                return NGX_ERROR;

            } else {
                server->down = down;
            }

            continue;
        }

        if (ngx_strncmp(args_n, "backup=", 7) == 0) {

            args_p = ngx_strchr((char *)args_n, '&');
            if (args_p != NULL) {
                backup = ngx_atoi(args_n + 7, args_p - args_n + 7);
            } else {
                backup = ngx_atoi(args_n + 7, args_end - args_n + 7);
            }

            if (backup != 0 && backup != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upconf_parse_args: invalid backup \"%V\"", 
                              &r->args);
                return NGX_ERROR;

            } else {
                server->backup = backup;
            }

            continue;
        }


        args_p = ngx_strchr((char *)args_n, '&');
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upconf_add_peer(ngx_http_request_t *r, ngx_http_server_t *server)
{
    ngx_uint_t                             n, w;
    ngx_http_upstream_server_t            *upstream_server;
    ngx_http_upstream_rr_peers_t          *peers=NULL, tmp_peers=NULL;
    ngx_http_upstream_srv_conf_t          *uscf;

    if ((uscf = ngx_http_upconf_lookup_upstream(&server->upstream)) == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_upconf_check_server(uscf, &server->ip_port) != -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upconf_add_peer: server \"%V\" exist", &server->ip_port);
        return NGX_ERROR;
    }

    if ((upstream_server = ngx_http_upconf_server(r, server)) != NULL) {
        return NGX_ERROR;
    }

    if (uscf->peer.data != NULL) {
        tmp_peers = (ngx_http_upstream_rr_peers_t *)uscf->peer.data;

    } else {
        return NGX_ERROR;
    }

    n = tmp_peers->number + 1;
    peers = ngx_calloc(sizeof(ngx_http_upstream_rr_peers_t)
                       + sizeof(ngx_http_upstream_rr_peer_t) * (n - 1), 
                       r->connection->log);
    if (peers == NULL) {
        goto invalid;
    }
    ngx_memcpy(peers, tmp_peers, sizeof(ngx_http_upstream_rr_peers_t) +
                + sizeof(ngx_http_upstream_rr_peer_t) * (tmp_peers->number));

    peers->peer[n - 1].sockaddr = upstream_server->addrs->sockaddr;
    peers->peer[n - 1].socklen = upstream_server->addrs->socklen;
    peers->peer[n - 1].name = upstream_server->addrs->name;
    peers->peer[n - 1].max_fails = upstream_server->max_fails;
    peers->peer[n - 1].fail_timeout = upstream_server->fail_timeout;
    peers->peer[n - 1].down = upstream_server->down;
    peers->peer[n - 1].weight = upstream_server->weight;
    peers->peer[n - 1].effective_weight = upstream_server->weight;
    peers->peer[n - 1].current_weight = 0;

#if (NGX_HTTP_UPSTREAM_CHECK) 
    ngx_uint_t index;
    index = ngx_http_upstream_check_add_dynamic_peer(cycle->pool, 
                                                         uscf, server->addrs);
    peers->peer[m].check_index = index;
#endif
    w = tmp_peers->total_weight + server->weight;

    peers->single = (n == 1);
    peers->number = n;
    peers->weighted = (w != n);
    peers->total_weight = w;

    uscf->peer.data = peers;
    peers->next = tmp_peers->next;

    if (r->start_sec != 0) {
        ngx_http_upconf_event_init(tmp_peers, upconf_server, NGX_ADD);

    } else {
        ngx_free(tmp_peers);
    }

    return NGX_OK;

invalid:
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "upconf_add_peer: add failed \"%V\"", &uscf->host);

    if (peers != NULL) {
        ngx_free(peers);
    }
    peers = NULL;

    uscf->peer.data = tmp_peers;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upconf_update_peer(ngx_cycle_t *cycle, ngx_channel_t *ch)
{
    ngx_uint_t                             n, w, index;
    ngx_http_upstream_server_t            *upstream_server;
    ngx_http_upstream_rr_peers_t          *peers=NULL;
    ngx_http_upstream_srv_conf_t          *uscf;

    if ((uscf = ngx_http_upconf_lookup_upstream(&server->upstream)) == NULL) {
        return NGX_ERROR;
    }

    if ((index = ngx_http_upconf_check_server(uscf, &server->ip_port)) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upconf_update_peer: server \"%V\" not exist", 
                      &server->ip_port);
        return NGX_ERROR;
    }

    if (uscf->peer.data != NULL) {
        peers = (ngx_http_upstream_rr_peers_t *)uscf->peer.data;

    } else {
        return NGX_ERROR;
    }

    n = peers->number;
    w = peers->total_weight - server->weight;

    peers->weighted = (w != n);
    peers->total_weight = w;
    peers->peer[n].max_fails = server->max_fails;
    peers->peer[n].fail_timeout = server->fail_timeout;
    peers->peer[n].down = server->down;
    peers->peer[n].weight = server->weight;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upconf_remove_peer(ngx_http_request_t *r, ngx_http_server_t *server)
{
    ngx_uint_t                             i, n, w, index;
    ngx_http_upstream_server_t            *upstream_server;
    ngx_http_upstream_rr_peers_t          *peers=NULL, tmp_peers=NULL;
    ngx_http_upstream_srv_conf_t          *uscf;

    if ((uscf = ngx_http_upconf_lookup_upstream(&server->upstream)) == NULL) {
        return NGX_ERROR;
    }

    if ((index = ngx_http_upconf_check_server(uscf, &server->ip_port)) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upconf_remove_peer: server \"%V\" not exist", 
                      &server->ip_port);
        return NGX_ERROR;
    }

    if (uscf->peer.data != NULL) {
        tmp_peers = (ngx_http_upstream_rr_peers_t *)uscf->peer.data;

    } else {
        return NGX_ERROR;
    }

    n = tmp_peers->number - 1;
    w = tmp_peers->total_weight - server->weight;

    peers = ngx_calloc(sizeof(ngx_http_upconf_rr_peers_t)
                       + sizeof(ngx_http_upconf_rr_peer_t) * (n - 1), 
                       r->connection->log);

    if (peers == NULL) {
        goto invalid;
    }

    peers->single = (n == 1);
    peers->number = n;
    peers->weighted = (w != n);
    peers->total_weight = w;
    peers->name = &uscf->host;

    n = 0;
    for (i = 0; i < tmp_peers->number; i++) {
        if (index == i) {

#if (NGX_HTTP_UPSTREAM_CHECK) 

            ngx_addr_t addr;
            addr.sockaddr = tmp_peers->peer[i].sockaddr;
            addr.socklen = tmp_peers->peer[i].socklen;
            addr.name = tmp_peers->peer[i].name;
            ngx_http_upstream_check_delete_dynamic_peer(tmp_peers->name, &addr);

#endif

            tmp_peers->peer[i].down = NGX_MAX_VALUE;
            continue;
        }

        peers->peer[n].sockaddr = tmp_peers->peer[i].sockaddr;
        peers->peer[n].socklen = tmp_peers->peer[i].socklen;
        peers->peer[n].name.len = tmp_peers->peer[i].name.len;
        peers->peer[n].name.data = tmp_peers->peer[i].name.data;
        peers->peer[n].max_fails = tmp_peers->peer[i].max_fails;
        peers->peer[n].fail_timeout = tmp_peers->peer[i].fail_timeout;
        peers->peer[n].down = tmp_peers->peer[i].down;
        peers->peer[n].weight = tmp_peers->peer[i].weight;
        peers->peer[n].effective_weight = tmp_peers->peer[i].effective_weight;
        peers->peer[n].current_weight = tmp_peers->peer[i].current_weight;

#if (NGX_HTTP_UPSTREAM_CHECK) 
        peers->peer[n].check_index = tmp_peers->peer[i].check_index;
#endif

        n++;
    }

    uscf->peer.data = peers;

    /* backup servers */
    peers->next = tmp_backup;

    ngx_http_upconf_event_init(tmp_peers, upstream_host, NGX_DEL);

    return NGX_OK;

invalid:
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                    "upstream_remove_server remove failed \"%V\"",
                    &server->ip_port);

    if (peers != NULL) {
        ngx_free(peers);
    }

    uscf->peer.data = tmp_peers;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_upconf_check_server(ngx_http_upstream_srv_conf_t *uscf, 
    ngx_str_t *ip_port)
{
    ngx_uint_t                          i;
    ngx_http_upstream_rr_peers_t       *peers = NULL;

    if (uscf->peer.data != NULL) {
        peers = (ngx_http_upstream_rr_peers_t *)uscf->peer.data;

    } else {
        return -1;
    }

    for (i = 0; i < peers->number; j++) {

        if (ngx_memcmp(peers->peer[i].name.data, 
                       ip_port->data, peers->peer[i].name.len) 
            == 0) 
        {
                return i;
        }
    }

    return -1;
}


static void
ngx_http_upconf_event_init(ngx_http_upstream_rr_peers_t *tmp_peers, 
        ngx_http_upconf_host_t *upstream_host, ngx_flag_t flag)
{
    ngx_time_t                                  *tp;
    ngx_delay_event_t                           *delay_event;

    delay_event = ngx_calloc(sizeof(*delay_event), ngx_cycle->log);
    if (delay_event == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "dynamic_update_upconf_event_init: calloc failed");
    }

    tp = ngx_timeofday();
    delay_event->start_sec = tp->sec;
    delay_event->start_msec = tp->msec;

    if (flag == NGX_ADD) {
        delay_event->delay_delete_ev.handler = ngx_http_upconf_add_delay_del;
        delay_event->delay_delete_ev.log = ngx_cycle->log;
        delay_event->delay_delete_ev.data = delay_event;
        delay_event->delay_delete_ev.timer_set = 0;

        ngx_queue_insert_head(&upstream_host->add_ev, &delay_event->queue);
    } else {

        delay_event->delay_delete_ev.handler = ngx_http_upconf_remove_delay_del;
        delay_event->delay_delete_ev.log = ngx_cycle->log;
        delay_event->delay_delete_ev.data = delay_event;
        delay_event->delay_delete_ev.timer_set = 0;

        ngx_queue_insert_head(&upstream_host->delete_ev, &delay_event->queue);
    }

    delay_event->data = tmp_peers;
    ngx_add_timer(&delay_event->delay_delete_ev, NGX_DELAY_DELETE);

    return;
}


static void
ngx_http_upconf_add_delay_del(ngx_event_t *event)
{
    ngx_uint_t                     i;
    ngx_connection_t              *c;
    ngx_delay_event_t             *delay_event;
    ngx_http_request_t            *r=NULL;
    ngx_http_log_ctx_t            *ctx=NULL;
    ngx_http_upconf_rr_peers_t  *tmp_peers=NULL, *tmp_backup=NULL;

    delay_event = event->data;

    c = ngx_cycle->connections;
    for (i = 0; i < ngx_cycle->connection_n; i++) {

        if (c[i].fd == (ngx_socket_t) -1) {
            continue;
        } else {

            if (c[i].log->data != NULL) {
                ctx = c[i].log->data;
                r = ctx->current_request;
            }
        }

        if (r) {
            if (r->start_sec < delay_event->start_sec) {
                ngx_add_timer(&delay_event->delay_delete_ev, NGX_DELAY_DELETE);
                return;
            }

            if (r->start_sec == delay_event->start_sec) {

                if (r->start_msec <= delay_event->start_msec) {
                    ngx_add_timer(&delay_event->delay_delete_ev, NGX_DELAY_DELETE);
                    return;
                }
            }
        }
    }

    tmp_peers = delay_event->data;
    tmp_backup = tmp_peers->next;

    if (tmp_peers != NULL) {

        ngx_free(tmp_peers);
        tmp_peers = NULL;
    }

    if (tmp_backup && tmp_backup->number > 0) {
 
        ngx_free(tmp_backup);
        tmp_backup = NULL;
    }

    ngx_queue_remove(&delay_event->queue);
    ngx_free(delay_event);

    delay_event = NULL;

    return;
}


static void
ngx_http_upconf_remove_delay_del(ngx_event_t *event)
{
    ngx_uint_t                    i;
    ngx_connection_t              *c;
    ngx_delay_event_t             *delay_event;
    ngx_http_request_t            *r=NULL;
    ngx_http_log_ctx_t            *ctx=NULL;
    ngx_http_upconf_rr_peers_t  *tmp_peers=NULL;

    u_char *namep = NULL;
    struct sockaddr *saddr = NULL;

    delay_event = event->data;
    tmp_peers = delay_event->data;

    c = ngx_cycle->connections;
    for (i = 0; i < ngx_cycle->connection_n; i++) {

        if (c[i].fd == (ngx_socket_t) -1) {
            continue;
        } else {

            if (c[i].log->data != NULL) {
                ctx = c[i].log->data;
                r = ctx->request;
            }
        }

        if (r) {
            if (r->start_sec < delay_event->start_sec) {
                ngx_add_timer(&delay_event->delay_delete_ev, NGX_DELAY_DELETE);
                return;
            }

            if (r->start_sec == delay_event->start_sec) {

                if (r->start_msec <= delay_event->start_msec) {
                    ngx_add_timer(&delay_event->delay_delete_ev, NGX_DELAY_DELETE);
                    return;
                }
            }
        }
    }

    if (tmp_peers != NULL) {
        for (i = 0; i < tmp_peers->number; i++) {

            if (tmp_peers->peer[i].check_index != NGX_MAX_VALUE) {
                continue;
            }

            saddr = tmp_peers->peer[i].sockaddr;
            if (saddr != NULL) {
                ngx_free(saddr);

            } else {
                continue;
            }

            namep = tmp_peers->peer[i].name.data;
            if (namep != NULL) {
                ngx_free(namep);
            }

            saddr = NULL, namep = NULL;
        }
    }

    if (tmp_peers != NULL) {
        ngx_free(tmp_peers);
        tmp_peers = NULL;
    }


    ngx_queue_remove(&delay_event->queue);
    ngx_free(delay_event);

    delay_event = NULL;

    return;
}


static void *
ngx_http_upconf_server(ngx_http_request_t *r, ngx_http_server_t *server)
{
    u_char                          *port, *p, *last, *pp;
    ngx_int_t                        n;
    ngx_addr_t                      *addrs;
    ngx_http_upstream_server_t      *upstream_server;

    struct sockaddr_in  *sin;

    upstream_server = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_server_t));

    p = server->ip_port.data;
    last = p + ngx_strlen(p);

    port = ngx_strlchr(p, last, ':');
    if (port == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                      "upconf_server: has no port in %s", p);
        return NULL;
    }

    n = ngx_atoi(port + 1, last - port - 1);
    if (n < 1 || n > 65535) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                      "upconf_server: invalid port in %s", p);
        return NULL;
    }

    sin = ngx_calloc(sizeof(struct sockaddr_in), cycle->log);
    if (sin == NULL) {
        goto invalid;
    }

    sin->sin_family = AF_INET;
    sin->sin_port = htons((in_port_t) n);
    sin->sin_addr.s_addr = ngx_inet_addr(p, port - p);

    if (sin->sin_addr.s_addr == INADDR_NONE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                      "upconf_server: invalid ip in %s", p);
        ngx_free(sin);
        return NULL;
    }

    addrs = ngx_calloc(sizeof(ngx_addr_t), cycle->log);
    if (addrs == NULL) {
        return NULL;
    }

    addrs->sockaddr = (struct sockaddr *) sin;
    addrs->socklen = sizeof(struct sockaddr_in);

    pp = ngx_calloc(last - p, cycle->log);
    if (pp == NULL) {
        goto invalid;
    }
    addrs->name.len = ngx_sprintf(pp, "%s", p) - pp;
    addrs->name.data = pp;

    ngx_memzero(upstream_server, sizeof(ngx_http_upstream_server_t));

    upstream_server->addrs = addrs;
    upstream_server->naddrs = 1;
    upstream_server->down = server->down;
    upstream_server->backup = server->backup;
    upstream_server->weight = server->weight;
    upstream_server->max_fails = server->max_fails;
    upstream_server->fail_timeout = server->fail_timeout;

    return upstream_server;

invalid:

    if (server->addrs->sockaddr != NULL) {
        ngx_free(server->addrs->sockaddr);
    }
    if (server->addrs->name.data != NULL) {
        ngx_free(server->addrs->name.data);
        
    ngx_free(upstream_server->addrs);

    return NULL;
}


static void *
ngx_http_upconf_lookup_upstream(ngx_str_t *upstream_name)
{
    ngx_http_upstream_srv_conf_t         **uscfp, *uscf;
    ngx_http_upstream_main_conf_t         *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len == upstream_name->len
            && ngx_strncasecmp(uscfp[i]->host.data, upstream_name->data, 
               uscfp[i]->host.len) == 0)
        {
            break;
        }
    }

    if (i == umcf->upstreams.nelts) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upconf_lookup_upstream: no upstream \"%V\"", upstream_name);
        return NULL;
    }

    return uscfp[i];
}


static void *
ngx_http_upconf_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upconf_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->upstream_conf = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_upconf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upconf_loc_conf_t *prev = parent;
    ngx_http_upconf_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->upstream_conf, prev->upstream_conf, 0);

    ngx_conf_merge_str_value(conf->upconf_dump_path, prev->upconf_dump_path, "/tmp");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upconf_init_process(ngx_cycle_t *cycle)
{
    u_char                                   *server_file;
    ngx_uint_t                                i;
    ngx_http_upstream_srv_conf_t            **uscfp;
    ngx_http_upstream_main_conf_t            *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        ngx_http_upconf_init_peers(cycle, uscfp[i]);

        ngx_http_upconf_parse_dump_file(uscfp[i], server_file);

    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upconf_init_peers(ngx_cycle_t *cycle, 
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_uint_t                          i, n, len;
    ngx_http_upstream_rr_peers_t       *peers = NULL, *tmp_peers = NULL;

    u_char *namep = NULL;
    struct sockaddr *saddr = NULL;
    len = sizeof(struct sockaddr);

    ngx_queue_init(&upconf_server->add_ev);
    ngx_queue_init(&upconf_server->delete_ev);

    if (uscf->peer.data != NULL) {
        tmp_peers = (ngx_http_upstream_rr_peers_t *)uscf->peer.data;
    }

    if (tmp_peers) {
        n = tmp_peers->number;

        peers = ngx_calloc(sizeof(ngx_http_upstream_rr_peers_t)
                           + sizeof(ngx_http_upstream_rr_peer_t) * (n - 1), 
                           cycle->log);
        if (peers == NULL) {
            goto invalid;
        }

        peers->single = tmp_peers->single;
        peers->number = tmp_peers->number;
        peers->weighted = tmp_peers->weighted;
        peers->total_weight = tmp_peers->total_weight;
        peers->name = tmp_peers->name;

        n = 0;
        for (i = 0; i < tmp_peers->number; i++) {

            if ((saddr = ngx_calloc(len, cycle->log)) == NULL) {
                goto invalid;
            }
            ngx_memcpy(saddr, tmp_peers->peer[i].sockaddr, len);
            peers->peer[i].sockaddr = saddr;

            peers->peer[i].socklen = tmp_peers->peer[i].socklen;
            peers->peer[i].name.len = tmp_peers->peer[i].name.len;

            if ((namep = ngx_calloc(tmp_peers->peer[i].name.len,
                                        cycle->log)) == NULL) {
                goto invalid;
            }
            ngx_memcpy(namep, tmp_peers->peer[i].name.data,
                        tmp_peers->peer[i].name.len);
            peers->peer[i].name.data = namep;

            peers->peer[i].max_fails = tmp_peers->peer[i].max_fails;
            peers->peer[i].fail_timeout = tmp_peers->peer[i].fail_timeout;
            peers->peer[i].down = tmp_peers->peer[i].down;
            peers->peer[i].weight = tmp_peers->peer[i].weight;
            peers->peer[i].effective_weight = tmp_peers->peer[i].effective_weight;
            peers->peer[i].current_weight = tmp_peers->peer[i].current_weight;

#if (NGX_HTTP_UPSTREAM_CHECK) 
            peers->peer[i].check_index = tmp_peers->peer[i].check_index;
#endif
        }

        uscf->peer.data = peers;
        peers->next = tmp_peers->next;

        ngx_pfree(cycle->pool, tmp_peers);
    }

    return NGX_OK;

invalid:
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                  "upconf_init_peers: copy failed \"%V\"", &uscf->host);

    if (peers != NULL) {
        ngx_free(peers);
    }
    uscf->peer.data = tmp_peers;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_upconf_parse_dump_file(ngx_http_upstream_srv_conf_t *uscf, 
    u_char * server_file)
{
    char                        *prev = NULL, *delimiter = NULL, read_line[1024];
    ngx_int_t                    max_fails;
    ngx_str_t                    s;
    ngx_pool_t                  *pool;
    ngx_connection_t             connection;
    ngx_http_server_t            server;
    ngx_http_request_t           r;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ngx_cycle->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upconf_parse_dump_file: alloc pool failed");
        return NGX_ERROR;
    }

    r.pool = pool;
    connection.log = ngx_cycle->log;
    r.connection = &connection;
    r.start_sec = 0;

    FILE *fp = ngx_fopen((char *)server_file, "r");
    if (fp == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "upconf_parse_dump_file: open dump file \"%s\" failed", 
                      server_file);
        ngx_destroy_pool(pool);

        return NGX_ERROR;
    }

    while (ngx_fgets(read_line, 1024, fp) != NULL) {

        prev = read_line;
        while(*prev != ';' && *prev != '\0') {

            if (ngx_strncmp(prev, "server", 6) == 0) {
                prev += 7;
                delimiter = ngx_strchr(prev, ' ');
                if (delimiter == NULL) {
                    delimiter = ngx_strchr(prev, ';');
                }
                if (delimiter == NULL) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                                  "server format error: \"%s\" ", read_line);
                    break;
                }

                server->ip_port.len = delimiter - prev;
                server->ip_port.data = ngx_pcalloc(pool, server->ip_port.len);
                if (server->ip_port.data == NULL) {
                    ngx_log_error(NGX_LOG_ERR, pool->log, 0, 
                                  "upconf_init_peers: memory alloc error");
                    return NGX_ERROR;
                }
                ngx_memmove(server->ip_port.data, prev, server->ip_port.len);

                server->upstream = uscf->host;

                /* default value, server attribute */
                server->weight = 1;
                server->max_fails = 2;
                server_conf->fail_timeout = 10;

                server->down = 0;
                server_conf->backup = 0;

                prev = delimiter;
                delimiter = NULL;

                continue;
            }

            if (ngx_strncmp(prev, "weight=", 7) == 0) {
                prev += 7;
                delimiter = ngx_strchr(prev, ' ');
                if (delimiter == NULL) {
                    delimiter = ngx_strchr(prev, ';');
                }

                if (delimiter == NULL) {
                    continue;
                }

                server->weight = ngx_atoi((u_char *)prev, 
                                          (size_t)(delimiter - prev));

                if (server->weight < 0) {
                    server->weight = 1;
                }
                prev = delimiter;
                delimiter = NULL;

                continue;
            }

            if (ngx_strncmp(prev, "max_fails=", 10) == 0) {
                prev += 10;
                delimiter = ngx_strchr(prev, ' ');
                if (delimiter == NULL) {
                    delimiter = ngx_strchr(prev, ';');
                }

                if (delimiter == NULL) {
                    continue;
                }

                max_fails = ngx_atoi((u_char *)prev, 
                                     (size_t)(delimiter - prev));

                if (max_fails < 0) {
                    server->max_fails = 2;

                } else {
                    server->max_fails = max_fails;
                }
                prev = delimiter;
                delimiter = NULL;

                continue;
            }

            if (ngx_strncmp(prev, "fail_timeout=", 13) == 0) {
                prev += 13;
                delimiter = ngx_strchr(prev, ' ');
                if (delimiter == NULL) {
                    delimiter = ngx_strchr(prev, ';');
                }

                if (delimiter == NULL) {
                    continue;
                }

                s.data = (u_char *)prev;
                s.len = delimiter - prev;
                server->fail_timeout = ngx_parse_time(&s, 1);

                if (server->fail_timeout < 0) {
                    server->fail_timeout = 10;
                }
                prev = delimiter;
                delimiter = NULL;

                continue;
            }

            prev++;
        }

        ngx_http_upconf_add_peer(&r, &server);
    }
    ngx_fclose(fp);

    ngx_destroy_pool(pool);

    return NGX_OK;
}


void
ngx_http_upconf_finalize_request(ngx_http_request_t *r)
{
    ngx_int_t                              len;
    ngx_buf_t                             *b = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0, 
                               "upstream add succeed finalize_success");

    len = ngx_strlen(add_succeed);

    b = ngx_create_temp_buf(r->pool, len);
    ngx_sprintf(b->pos, "%s", add_succeed);
    b->last = b->pos + len;

    b->last_buf = 1;
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
 
    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    ngx_int_t ret = ngx_http_send_header(r);
    ret = ngx_http_output_filter(r, &out);
 
    ngx_http_finalize_request(r, ret);
    return;
}
