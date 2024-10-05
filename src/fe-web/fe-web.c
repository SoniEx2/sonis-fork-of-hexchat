/* LipstixChat
 * Copyright (C) 2024 Soni L.
 * X-Chat
 * Copyright (C) 1998 Peter Zelezny.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* The purpose of the web-based frontend is that you don't need to migrate
 * gtk versions if you drop gtk altogether.
 *
 * Yeah, really.
 *
 * The cool thing about the web is that it's unlikely to change much in the
 * next 25 years. Websites from the early 2000s still work more or less fine
 * at the time of writing this. (Websites from the 2010s don't work as fine,
 * thanks Flash, but at least that's actually dead now.)
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#if 0
#ifdef WIN32
#include <io.h>
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#else
#include <unistd.h>
#include <sys/time.h>
#endif
#endif
#include <sys/types.h>
#include <ctype.h>
#include <glib-object.h>
#include <libsoup/soup.h>
#include "../common/hexchat.h"
#include "../common/hexchatc.h"
#include "../common/cfgfiles.h"
#include "../common/outbound.h"
#include "../common/util.h"
#include "../common/fe.h"
#include "fe-web.h"


static int done = FALSE;		  /* finished ? */

static char cookie_key[65] = {0};

static void
init_cookie_key (void)
{
	/* TODO */
}

static void
free_uri_data (gpointer data)
{
	g_uri_unref (data);
}

static int done_intro = 0;

void
fe_new_window (struct session *sess, int focus)
{
	char buf[512];

	current_sess = sess;

	if (!sess->server->front_session)
		sess->server->front_session = sess;
	if (!sess->server->server_session)
		sess->server->server_session = sess;
	if (!current_tab || focus)
		current_tab = sess;

	if (done_intro)
		return;
	done_intro = 1;

	g_snprintf (buf, sizeof (buf),
				"\n"
				" \017HexChat-Text \00310"PACKAGE_VERSION"\n"
				" \017Running on \00310%s\n",
				get_sys_str (1));
	fe_print_text (sess, buf, 0, FALSE);

	fe_print_text (sess, "\n\nCompiled in Features\0032:\017 "
#ifdef USE_PLUGIN
	"Plugin "
#endif
#ifdef ENABLE_NLS
	"NLS "
#endif
#ifdef USE_OPENSSL
	"OpenSSL "
#endif
	"\n\n", 0, FALSE);
	fflush (stdout);
}

static int
get_stamp_str (time_t tim, char *dest, int size)
{
	return strftime_validated (dest, size, prefs.hex_stamp_text_format, localtime (&tim));
}

static int
timecat (char *buf, time_t stamp)
{
	char stampbuf[64];

	/* set the stamp to the current time if not provided */
	if (!stamp)
		stamp = time (0);

	get_stamp_str (stamp, stampbuf, sizeof (stampbuf));
	strcat (buf, stampbuf);
	return strlen (stampbuf);
}

static int
check_cookies (const char *cookies)
{
	/* fun fact, if browsers ever add 'reverse http/2', we can yeet this */
	/* ps. there's no cookie isolation between different ports,
	 * this just prevents arbitrary websites from making useful requests */
	if (!cookies)
		return 0;

	if (!g_str_has_prefix (cookies, "csrfkey="))
		return 0;

	cookies = cookies + strlen ("csrfkey=");

	return !strcmp (cookies, cookie_key);
}

#define REDIR_MSG "<html><head><title></title></head><body>Redirecting to <a href=\"/\">/</a>. This app requires session cookies.</body></html>\n"

static void
server_callback (SoupServer *server, SoupServerMessage *msg, const char *path, GHashTable *query, gpointer user_data)
{
	SoupMessageHeaders *reqheaders;
	SoupMessageHeaders *resheaders;
	const char *cookies;

	reqheaders = soup_server_message_get_request_headers (msg);
	resheaders = soup_server_message_get_response_headers (msg);
	cookies = soup_message_headers_get_one (reqheaders, "Cookie");
	if (!check_cookies (cookies))
	{
		g_print("authorizing new client");
		soup_server_message_set_redirect (msg, 303, "/");
		soup_server_message_set_response (msg, "text/html", SOUP_MEMORY_STATIC, REDIR_MSG, strlen (REDIR_MSG));
		soup_message_headers_append (resheaders, "Set-Cookie", "csrfkey=; SameSite=Strict; HttpOnly");
		return;
	}

	g_print("got %s request for: %s\n", soup_server_message_get_method (msg), path);
	if (!strcmp("/", path))
	{
		g_print("handling main page");
	}
}

void
fe_print_text (struct session *sess, char *text, time_t stamp,
			   gboolean no_activity)
{
}

void
fe_timeout_remove (int tag)
{
	g_source_remove (tag);
}

int
fe_timeout_add (int interval, void *callback, void *userdata)
{
	return g_timeout_add (interval, (GSourceFunc) callback, userdata);
}

int
fe_timeout_add_seconds (int interval, void *callback, void *userdata)
{
	return g_timeout_add_seconds (interval, (GSourceFunc) callback, userdata);
}

void
fe_input_remove (int tag)
{
	g_source_remove (tag);
}

int
fe_input_add (int sok, int flags, void *func, void *data)
{
	int tag, type = 0;
	GIOChannel *channel;

#ifdef G_OS_WIN32
	if (flags & FIA_FD)
		channel = g_io_channel_win32_new_fd (sok);
	else
		channel = g_io_channel_win32_new_socket (sok);
#else
	channel = g_io_channel_unix_new (sok);
#endif

	if (flags & FIA_READ)
		type |= G_IO_IN | G_IO_HUP | G_IO_ERR;
	if (flags & FIA_WRITE)
		type |= G_IO_OUT | G_IO_ERR;
	if (flags & FIA_EX)
		type |= G_IO_PRI;

	tag = g_io_add_watch (channel, type, (GIOFunc) func, data);
	g_io_channel_unref (channel);

	return tag;
}

/* === command-line parameter parsing : requires glib 2.6 === */

static char *arg_cfgdir = NULL;
static gint arg_show_autoload = 0;
static gint arg_show_config = 0;
static gint arg_show_version = 0;
static gint arg_dont_open = 0;

static const GOptionEntry gopt_entries[] = 
{
 {"no-auto",	'a', 0, G_OPTION_ARG_NONE,	&arg_dont_autoconnect, N_("Don't auto connect to servers"), NULL},
 {"cfgdir",	'd', 0, G_OPTION_ARG_STRING,	&arg_cfgdir, N_("Use a different config directory"), "PATH"},
 {"no-plugins",	'n', 0, G_OPTION_ARG_NONE,	&arg_skip_plugins, N_("Don't auto load any plugins"), NULL},
 {"plugindir",	'p', 0, G_OPTION_ARG_NONE,	&arg_show_autoload, N_("Show plugin/script auto-load directory"), NULL},
 {"configdir",	'u', 0, G_OPTION_ARG_NONE,	&arg_show_config, N_("Show user config directory"), NULL},
 {"url",	 0,  G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING,	&arg_url, N_("Open an irc://server:port/channel URL"), "URL"},
 {"version",	'v', 0, G_OPTION_ARG_NONE,	&arg_show_version, N_("Show version information"), NULL},
 /*{"no-open",	'o', 0, G_OPTION_ARG_NONE,	&arg_dont_open, N_("Don't open"), NULL},*/
 {G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_STRING_ARRAY, &arg_urls, N_("Open an irc://server:port/channel?key URL"), "URL"},
 {NULL}
};

int
fe_args (int argc, char *argv[])
{
	GError *error = NULL;
	GOptionContext *context;

#ifdef ENABLE_NLS
	bindtextdomain (GETTEXT_PACKAGE, LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);
#endif

	context = g_option_context_new (NULL);
	g_option_context_add_main_entries (context, gopt_entries, GETTEXT_PACKAGE);
	g_option_context_parse (context, &argc, &argv, &error);

	if (error)
	{
		if (error->message)
			printf ("%s\n", error->message);
		return 1;
	}

	g_option_context_free (context);

	if (arg_show_version)
	{
		printf (PACKAGE_NAME" "PACKAGE_VERSION"\n");
		return 0;
	}

	if (arg_show_autoload)
	{
#ifndef USE_PLUGIN
		printf (PACKAGE_NAME" was build without plugin support\n");
		return 1;
#else
#ifdef WIN32
		/* see the chdir() below */
		char *sl, *exe = g_strdup (argv[0]);
		sl = strrchr (exe, '\\');
		if (sl)
		{
			*sl = 0;
			printf ("%s\\plugins\n", exe);
		}
		g_free (exe);
#else
		printf ("%s\n", HEXCHATLIBDIR);
#endif
#endif
		return 0;
	}

	if (arg_show_config)
	{
		printf ("%s\n", get_xdir ());
		return 0;
	}

	if (arg_cfgdir)	/* we want filesystem encoding */
	{
		g_free (xdir);
		xdir = strdup (arg_cfgdir);
		if (xdir[strlen (xdir) - 1] == '/')
			xdir[strlen (xdir) - 1] = 0;
		g_free (arg_cfgdir);
	}

	return -1;
}

void
fe_init (void)
{
	/* FIXME: remove these once they're implemented */
	/* the following should be default generated, not enfoced in binary */
	prefs.hex_gui_tab_server = 0;
	prefs.hex_gui_autoopen_dialog = 0;
	/* except for these, there is no lag meter, there is no server list */
	prefs.hex_gui_lagometer = 0;
	prefs.hex_gui_slist_skip = 1;
}

void
fe_main (void)
{
	SoupServer *server;
	GSList *l, *li;
	int port = 0;

	main_loop = g_main_loop_new(NULL, FALSE);
	server = soup_server_new ("server-header", PACKAGE_NAME"/"PACKAGE_VERSION, NULL);
	if (!server)
	{
		/* ??? */
		abort();
	}
	if (!soup_server_listen_local (server, 0, SOUP_SERVER_LISTEN_IPV6_ONLY, NULL))
	{
		/* FIXME error handling */
		abort();
	}

	init_cookie_key();
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	l = soup_server_get_uris (server);
	for (li = l; li; li = li->next)
	{
		if (port != 0)
		{
			g_warning ("found multiple listen URIs, things may not work properly.");
			break;
		}
		port = g_uri_get_port (li->data);
		/* NOTE: this doesn't provide real csrf isolation between
		 * localhost services, but lets multiple instances coexist */
		g_print ("Listening on http://lipstixchat-%d.localhost:%d/\n", port, port);
		if (!arg_dont_open)
		{
			g_print ("Launching browser: not yet implemented.\n");
			/* TODO */
		}
	}
	g_slist_free_full (l, free_uri_data);

	g_main_loop_run(main_loop);

	return;
}

void
fe_exit (void)
{
	done = TRUE;
	g_main_loop_quit(main_loop);
}

void
fe_new_server (struct server *serv)
{
}

void
fe_message (char *msg, int flags)
{
	puts (msg);
}

void
fe_close_window (struct session *sess)
{
	session_free (sess);
	done = TRUE;
}

void
fe_beep (session *sess)
{
	putchar (7);
}

void
fe_add_rawlog (struct server *serv, char *text, int len, int outbound)
{
}
void
fe_set_topic (struct session *sess, char *topic, char *stripped_topic)
{
}
void
fe_cleanup (void)
{
}
void
fe_set_tab_color (struct session *sess, tabcolor col)
{
}
void
fe_update_mode_buttons (struct session *sess, char mode, char sign)
{
}
void
fe_update_channel_key (struct session *sess)
{
}
void
fe_update_channel_limit (struct session *sess)
{
}
int
fe_is_chanwindow (struct server *serv)
{
	return 0;
}

void
fe_add_chan_list (struct server *serv, char *chan, char *users, char *topic)
{
}
void
fe_chan_list_end (struct server *serv)
{
}
gboolean
fe_add_ban_list (struct session *sess, char *mask, char *who, char *when, int rplcode)
{
	return 0;
}
gboolean
fe_ban_list_end (struct session *sess, int rplcode)
{
	return 0;
}
void
fe_notify_update (char *name)
{
}
void
fe_notify_ask (char *name, char *networks)
{
}
void
fe_text_clear (struct session *sess, int lines)
{
}
void
fe_progressbar_start (struct session *sess)
{
}
void
fe_progressbar_end (struct server *serv)
{
}
void
fe_userlist_insert (struct session *sess, struct User *newuser, gboolean sel)
{
}
int
fe_userlist_remove (struct session *sess, struct User *user)
{
	return 0;
}
void
fe_userlist_rehash (struct session *sess, struct User *user)
{
}
void
fe_userlist_numbers (struct session *sess)
{
}
void
fe_userlist_clear (struct session *sess)
{
}
void
fe_userlist_set_selected (struct session *sess)
{
}
void
fe_dcc_add (struct DCC *dcc)
{
}
void
fe_dcc_update (struct DCC *dcc)
{
}
void
fe_dcc_remove (struct DCC *dcc)
{
}
void
fe_clear_channel (struct session *sess)
{
}
void
fe_session_callback (struct session *sess)
{
}
void
fe_server_callback (struct server *serv)
{
}
void
fe_url_add (const char *text)
{
}
void
fe_pluginlist_update (void)
{
}
void
fe_buttons_update (struct session *sess)
{
}
void
fe_dlgbuttons_update (struct session *sess)
{
}
void
fe_dcc_send_filereq (struct session *sess, char *nick, int maxcps, int passive)
{
}
void
fe_set_channel (struct session *sess)
{
}
void
fe_set_title (struct session *sess)
{
}
void
fe_set_nonchannel (struct session *sess, int state)
{
}
void
fe_set_nick (struct server *serv, char *newnick)
{
}
void
fe_change_nick (struct server *serv, char *nick, char *newnick)
{
}
void
fe_ignore_update (int level)
{
}
int
fe_dcc_open_recv_win (int passive)
{
	return FALSE;
}
int
fe_dcc_open_send_win (int passive)
{
	return FALSE;
}
int
fe_dcc_open_chat_win (int passive)
{
	return FALSE;
}
void
fe_userlist_hide (session * sess)
{
}
void
fe_lastlog (session *sess, session *lastlog_sess, char *sstr, gtk_xtext_search_flags flags)
{
}
void
fe_set_lag (server * serv, long lag)
{
}
void
fe_set_throttle (server * serv)
{
}
void
fe_set_away (server *serv)
{
}
void
fe_serverlist_open (session *sess)
{
}
void
fe_get_bool (char *title, char *prompt, void *callback, void *userdata)
{
}
void
fe_get_str (char *prompt, char *def, void *callback, void *ud)
{
}
void
fe_get_int (char *prompt, int def, void *callback, void *ud)
{
}
void
fe_idle_add (void *func, void *data)
{
	g_idle_add (func, data);
}
void
fe_ctrl_gui (session *sess, fe_gui_action action, int arg)
{
	/* only one action type handled for now, but could add more */
	switch (action)
	{
	/* gui focus is really the only case hexchat-text needs to worry about */
	case FE_GUI_FOCUS:
		current_sess = sess;
		current_tab = sess;
		sess->server->front_session = sess;
		break;
	default:
		break;
	}
}
int
fe_gui_info (session *sess, int info_type)
{
	return -1;
}
void *
fe_gui_info_ptr (session *sess, int info_type)
{
	return NULL;
}
void fe_confirm (const char *message, void (*yesproc)(void *), void (*noproc)(void *), void *ud)
{
}
char *fe_get_inputbox_contents (struct session *sess)
{
	return NULL;
}
void fe_set_inputbox_contents (struct session *sess, char *text)
{
}
int fe_get_inputbox_cursor (struct session *sess)
{
	return 0;
}
void fe_set_inputbox_cursor (struct session *sess, int delta, int pos)
{
}
void fe_open_url (const char *url)
{
}
void fe_menu_del (menu_entry *me)
{
}
char *fe_menu_add (menu_entry *me)
{
	return NULL;
}
void fe_menu_update (menu_entry *me)
{
}
void fe_uselect (struct session *sess, char *word[], int do_clear, int scroll_to)
{
}
void
fe_server_event (server *serv, int type, int arg)
{
}
void
fe_flash_window (struct session *sess)
{
}
void fe_get_file (const char *title, char *initial,
				 void (*callback) (void *userdata, char *file), void *userdata,
				 int flags)
{
}
void fe_tray_set_flash (const char *filename1, const char *filename2, int timeout){}
void fe_tray_set_file (const char *filename){}
void fe_tray_set_icon (feicon icon){}
void fe_tray_set_tooltip (const char *text){}
void fe_userlist_update (session *sess, struct User *user){}
void
fe_open_chan_list (server *serv, char *filter, int do_refresh)
{
	serv->p_list_channels (serv, filter, 1);
}
const char *
fe_get_default_font (void)
{
	return NULL;
}
