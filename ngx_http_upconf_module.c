/*
 * Copyright (C) 2015 Weibo Group Holding Limited
 * Copyright (C) 2015 Xiaokai Wang (xiaokai.wang@live.com)
 */


#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>


typedef struct {
    ngx_str_t            method;
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
static ngx_int_t ngx_http_upconf_parse_args(ngx_str_t *args, 
    ngx_http_server_t *server);

static void *ngx_http_upconf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upconf_merge_loc_conf(ngx_conf_t *cf, void *parent, 
    void *child)

static ngx_int_t ngx_http_upconf_init_process(ngx_cycle_t *cycle);
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

    if (ngx_http_upconf_parse_args(&r->args, &server) != NGX_OK) {
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


ngx_int_t
ngx_http_upconf_add_peer(ngx_cycle_t *cycle,
    ngx_http_upconf_srv_conf_t *uscf, ngx_http_upconf_t *us)
{
    ngx_uint_t                     i, n, w, m;
    ngx_http_upconf_host_t      *upstream_host = NULL;
    ngx_http_upconf_rr_peers_t  *peers=NULL;

    for (i = 0; i < upconf->upconf.nelts; i++) {
        upstream_host = (ngx_http_upconf_host_t *)upconf->upconf.elts + i;

        if (uscf->host.len == upstream_host->upstream_name.len
            && ngx_strncasecmp(uscf->host.data, upstream_host->upstream_name.data, uscf->host.len)
               == 0)
        {
            break;
        }
    }

    peers = uscf->peer.data;

    if (us->naddrs) {

        n = us->naddrs + peers->number;
        w = us->naddrs * us->weight + peers->total_weight;

        if (n == 0) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                        "no servers to add in upstream_add_server \"%V\" in %s:%ui",
                        &uscf->host, uscf->file_name, uscf->line);
            return NGX_ERROR;
        }

        m = peers->number;

        peers->single = (n == 1);
        peers->number = n;
        peers->weighted = (w != n);
        peers->total_weight = w;

        for (i = 0; i < us->naddrs; i++) {
            if (us->backup) {
                    continue;
            }

            peers->peer[m].sockaddr = us->addrs[i].sockaddr;
            peers->peer[m].socklen = us->addrs[i].socklen;
            peers->peer[m].name = us->addrs[i].name;
            peers->peer[m].max_fails = us->max_fails;
            peers->peer[m].fail_timeout = us->fail_timeout;
            peers->peer[m].down = us->down;
            peers->peer[m].weight = us->weight;
            peers->peer[m].effective_weight = us->weight;
            peers->peer[m].current_weight = 0;

#if (NGX_HTTP_UPSTREAM_CHECK) 
            ngx_uint_t index = ngx_http_upconf_check_add_dynamic_peer(cycle->pool, uscf, &us->addrs[i]);
            peers->peer[m].check_index = index;
#endif

            m++;
        }

    }

    if (!upstream_host->update_label) {
        ngx_http_upconf_del_fake_peer(cycle, uscf);

        upstream_host->update_label = 1;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_upconf_update_peer(ngx_cycle_t *cycle, ngx_channel_t *ch)
{
    u_char                                  *port, *p, *last;
    ngx_int_t                                n, j;
    ngx_uint_t                               i;
    ngx_pool_t                              *pool;
    ngx_addr_t                              *addrs;
    ngx_http_upconf_t               us;
    ngx_http_upconf_srv_conf_t            *uscf, **uscfp;
    ngx_http_upconf_main_conf_t           *umcf;

    if (ch->naddrs <= 0) {
        return NGX_ERROR;
    }

    struct sockaddr_in  *sin;

    umcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upconf_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len == ch->host_len
            && ngx_strncasecmp(uscfp[i]->host.data, ch->host, ch->host_len)
               == 0)
        {
            break;
        }
    }

    uscf = uscfp[i];

    ngx_memzero(&us, sizeof(ngx_http_upconf_t));

    pool = ngx_create_pool(ngx_pagesize, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    addrs = ngx_pcalloc(pool, ch->naddrs * sizeof(ngx_addr_t));
    if (addrs == NULL) {
        goto invalid;
    }

    for (i = 0, j = 0; i < ch->naddrs; i++, j++) {
        p = ch->sockaddr[i];
        last = p + ngx_strlen(ch->sockaddr[i]);

        port = ngx_strlchr(p, last, ':');
        if(port == NULL) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                    "upstream_del_server: has no port in %s", p);
            j--;
            continue;
        }

        n = ngx_atoi(port + 1, last - port - 1);
        if (n < 1 || n > 65535) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, 
                    "upstream_del_server: invalid port in %s", p);
            j--;
            continue;
        }

        sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            goto invalid;
        }

        sin->sin_family = AF_INET;
        sin->sin_port = htons((in_port_t) n);
        sin->sin_addr.s_addr = ngx_inet_addr(p, port - p);

        if (sin->sin_addr.s_addr == INADDR_NONE) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, 
                    "upstream_del_server: invalid ip in %s", p);
            j--;
            continue;
        }

        addrs[j].sockaddr = (struct sockaddr *) sin;
        addrs[j].socklen = sizeof(struct sockaddr_in);

        p = ngx_pcalloc(pool, last - p);
        if (p == NULL) {
            goto invalid;
        }

        addrs[j].name.len = ngx_sprintf(p, "%s",
                                           ch->sockaddr[i]) - p;
        addrs[j].name.data = p;
    }

    us.addrs = addrs;
    us.naddrs = j;
    us.weight = 0;
    us.max_fails = 0;
    us.fail_timeout = 0;

    if (ngx_http_upconf_del_peer(cycle, uscf, &us) != NGX_OK) {
        goto invalid;
    }

    ngx_destroy_pool(pool);

    return NGX_OK;

invalid:
    ngx_destroy_pool(pool);

    return NGX_ERROR;

}


static ngx_int_t
ngx_http_upconf_del_peer(ngx_cycle_t *cycle,
    ngx_http_upconf_srv_conf_t *uscf, ngx_http_upconf_t *us)
{
    ngx_uint_t                     i, j, n, w, len;
    ngx_http_upconf_host_t      *upstream_host = NULL;
    ngx_http_upconf_rr_peers_t  *peers=NULL;
    ngx_http_upconf_rr_peers_t  *tmp_peers=NULL, *tmp_backup=NULL;

    len = sizeof(struct sockaddr);

    for (i = 0; i < upconf->upconf.nelts; i++) {
        upstream_host = (ngx_http_upconf_host_t *)upconf->upconf.elts + i;

        if (uscf->host.len == upstream_host->upstream_name.len
            && ngx_strncasecmp(uscf->host.data, upstream_host->upstream_name.data, uscf->host.len)
               == 0)
        {
            break;
        }
    }

    if (uscf->peer.data != NULL) {
        tmp_peers = (ngx_http_upconf_rr_peers_t *)uscf->peer.data;
        tmp_backup = tmp_peers->next;
    }

    if (tmp_peers) {
        n = 0;
        w = 0;

        if (tmp_peers->number < us->naddrs) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                        "no servers to del in upstream_del_server \"%V\" in %s:%ui",
                        &uscf->host, uscf->file_name, uscf->line);
            goto invalid;
        }

        n = tmp_peers->number - us->naddrs;
        w = tmp_peers->total_weight - us->naddrs * us->weight;

        peers = ngx_calloc(sizeof(ngx_http_upconf_rr_peers_t)
                        + sizeof(ngx_http_upconf_rr_peer_t) * (n - 1), cycle->log);

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
            for (j = 0; j < us->naddrs; j++) {
                if (ngx_memn2cmp((u_char *) tmp_peers->peer[i].sockaddr, 
                                 (u_char *) us->addrs[j].sockaddr, len, len)
                    == 0)
                {

#if (NGX_HTTP_UPSTREAM_CHECK) 
                    ngx_http_upconf_check_delete_dynamic_peer(
                                                 tmp_peers->name, &us->addrs[j]);
#endif

                    tmp_peers->peer[i].check_index = NGX_MAX_VALUE;
                    break;
                }
            }

            if (j == us->naddrs) {

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
        }

        uscf->peer.data = peers;

        /* backup servers */

        peers->next = tmp_backup;

        ngx_http_upconf_event_init(tmp_peers, upstream_host, NGX_DEL);

        return NGX_OK;
    }

    return NGX_OK;

invalid:
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                    "upstream_del_server del failed \"%V\" in %s:%ui",
                    &uscf->host, uscf->file_name, uscf->line);\

    if (peers != NULL) {
        ngx_http_upconf_dynamic_free(peers);
    }

    uscf->peer.data = tmp_peers;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_upconf_parse_args(ngx_str_t *args, ngx_http_server_t *server)
{
    return NGX_OK;
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
    ngx_uint_t                                i;
    ngx_http_upconf_host_t                 *upstream_host;
    ngx_http_upconf_srv_conf_t            **uscfp;
    ngx_http_upconf_main_conf_t            *umcf;
    ngx_http_upconf_ctx_t           *upstream_conf;

    umcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upconf_module);

    upstream_conf = ngx_pcalloc(cycle->pool, sizeof(*upstream_conf));
    if (ngx_array_init(&upstream_conf->upconf, cycle->pool, umcf->upstreams.nelts,
                sizeof(*upstream_host)) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "upstream_add_server_init_process: array_init error");

        return NGX_ERROR;
    }

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        upstream_host = ngx_array_push(&upstream_conf->upconf);

        upstream_host->upstream_name.len = uscfp[i]->host.len;
        upstream_host->upstream_name.data = uscfp[i]->host.data;

        ngx_queue_init(&upstream_host->add_ev);
        ngx_queue_init(&upstream_host->delete_ev);

        upstream_host->update_label = 0;
    }

    upconf = upstream_conf;

    return NGX_OK;
}


static void
ngx_http_upconf_dynamic_free(ngx_http_upstream_rr_peers_t *peers)
{
    if (peers != NULL) {
        ngx_free(peers);
        peers = NULL;
    }

    return;
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
