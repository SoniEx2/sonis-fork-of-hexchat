/* X-Chat
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define WANTSOCKET
#include "inet.h"

#ifdef WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#endif

#include "hexchat.h"
#include "fe.h"
#include "util.h"
#include "cfgfiles.h"
#include "chanopt.h"
#include "ignore.h"
#include "hexchat-plugin.h"
#include "inbound.h"
#include "plugin.h"
#include "plugin-identd.h"
#include "plugin-timer.h"
#include "notify.h"
#include "server.h"
#include "servlist.h"
#include "outbound.h"
#include "text.h"
#include "url.h"
#include "hexchatc.h"

#if ! GLIB_CHECK_VERSION (2, 36, 0)
#include <glib-object.h>			/* for g_type_init() */
#endif

GSList *popup_list = 0;
GSList *button_list = 0;
GSList *dlgbutton_list = 0;
GSList *command_list = 0;
GSList *ctcp_list = 0;
GSList *replace_list = 0;
GSList *sess_list = 0;
GSList *dcc_list = 0;
GSList *ignore_list = 0;
GSList *usermenu_list = 0;
GSList *urlhandler_list = 0;
GSList *tabmenu_list = 0;

/*
 * This array contains 5 double linked lists, one for each priority in the
 * "interesting session" queue ("channel" stands for everything but
 * SESS_DIALOG):
 *
 * [0] queries with hilight
 * [1] queries
 * [2] channels with hilight
 * [3] channels with dialogue
 * [4] channels with other data
 *
 * Each time activity happens the corresponding session is put at the
 * beginning of one of the lists.  The aim is to be able to switch to the
 * session with the most important/recent activity.
 */
GList *sess_list_by_lastact[5] = {NULL, NULL, NULL, NULL, NULL};


static int in_hexchat_exit = FALSE;
int hexchat_is_quitting = FALSE;
/* command-line args */
int arg_dont_autoconnect = FALSE;
int arg_skip_plugins = FALSE;
char *arg_url = NULL;
char **arg_urls = NULL;
char *arg_command = NULL;
gint arg_existing = FALSE;

#ifdef USE_DBUS
#include "dbus/dbus-client.h"
#include "dbus/dbus-plugin.h"
#endif /* USE_DBUS */

struct session *current_tab;
struct session *current_sess = 0;
struct hexchatprefs prefs;

/*
 * Update the priority queue of the "interesting sessions"
 * (sess_list_by_lastact).
 */
void
lastact_update(session *sess)
{
	int oldidx = sess->lastact_idx;
	int newidx = LACT_NONE;
	int dia = (sess->type == SESS_DIALOG);

	if (sess->tab_state & TAB_STATE_NEW_HILIGHT)
		newidx = dia? LACT_QUERY_HI: LACT_CHAN_HI;
	else if (sess->tab_state & TAB_STATE_NEW_MSG)
		newidx = dia? LACT_QUERY: LACT_CHAN;
	else if (sess->tab_state & TAB_STATE_NEW_DATA)
		newidx = dia? LACT_QUERY: LACT_CHAN_DATA;

	/* If already first at the right position, just return */
	if (oldidx == newidx &&
		 (newidx == LACT_NONE || g_list_index(sess_list_by_lastact[newidx], sess) == 0))
		return;

	/* Remove from the old position */
	if (oldidx != LACT_NONE)
		sess_list_by_lastact[oldidx] = g_list_remove(sess_list_by_lastact[oldidx], sess);

	/* Add at the new position */
	sess->lastact_idx = newidx;
	if (newidx != LACT_NONE)
		sess_list_by_lastact[newidx] = g_list_prepend(sess_list_by_lastact[newidx], sess);
	return;
}

/*
 * Extract the first session from the priority queue of sessions with recent
 * activity. Return NULL if no such session can be found.
 *
 * If filter is specified, skip a session if filter(session) returns 0. This
 * can be used for UI-specific needs, e.g. in fe-gtk we want to filter out
 * detached sessions.
 */
session *
lastact_getfirst(int (*filter) (session *sess))
{
	int i;
	session *sess = NULL;
	GList *curitem;

	/* 5 is the number of priority classes LACT_ */
	for (i = 0; i < 5 && !sess; i++)
	{
		curitem = sess_list_by_lastact[i];
		while (curitem && !sess)
		{
			sess = g_list_nth_data(curitem, 0);
			if (!sess || (filter && !filter(sess)))
			{
				sess = NULL;
				curitem = g_list_next(curitem);
			}
		}

		if (sess)
		{
			sess_list_by_lastact[i] = g_list_remove(sess_list_by_lastact[i], sess);
			sess->lastact_idx = LACT_NONE;
		}
	}
	
	return sess;
}

int
is_session (session * sess)
{
	return sess != NULL && (g_slist_find (sess_list, sess) ? 1 : 0);
}

session *
find_dialog (server *serv, char *nick)
{
	GSList *list = sess_list;
	session *sess;

	while (list)
	{
		sess = list->data;
		if (sess->server == serv && sess->type == SESS_DIALOG)
		{
			if (!serv->p_cmp (nick, sess->channel))
				return (sess);
		}
		list = list->next;
	}
	return NULL;
}

session *
find_channel (server *serv, char *chan)
{
	session *sess;
	GSList *list = sess_list;
	while (list)
	{
		sess = list->data;
		if ((serv == sess->server) && sess->type == SESS_CHANNEL)
		{
			if (!serv->p_cmp (chan, sess->channel))
				return sess;
		}
		list = list->next;
	}
	return NULL;
}

static void
lagcheck_update (void)
{
	server *serv;
	GSList *list = serv_list;
	
	if (!prefs.hex_gui_lagometer)
		return;

	while (list)
	{
		serv = list->data;
		if (serv->lag_sent)
			fe_set_lag (serv, -1);

		list = list->next;
	}
}

void
lag_check (void)
{
	server *serv;
	GSList *list = serv_list;
	unsigned long tim;
	char tbuf[128];
	time_t now = time (0);
	time_t lag;

	tim = make_ping_time ();

	while (list)
	{
		serv = list->data;
		if (serv->connected && serv->end_of_motd)
		{
			lag = now - serv->ping_recv;
			if (prefs.hex_net_ping_timeout != 0 && lag > prefs.hex_net_ping_timeout && lag > 0)
			{
				sprintf (tbuf, "%" G_GINT64_FORMAT, (gint64) lag);
				EMIT_SIGNAL (XP_TE_PINGTIMEOUT, serv->server_session, tbuf, NULL,
								 NULL, NULL, 0);
				if (prefs.hex_net_auto_reconnect)
					serv->auto_reconnect (serv, FALSE, -1);
			}
			else
			{
				g_snprintf (tbuf, sizeof (tbuf), "LAG%lu", tim);
				serv->p_ping (serv, "", tbuf);
				
				if (!serv->lag_sent)
				{
					serv->lag_sent = tim;
					fe_set_lag (serv, -1);
				}
			}
		}
		list = list->next;
	}
}

static int
away_check (void)
{
	session *sess;
	GSList *list;
	int full, sent, loop = 0;

	if (!prefs.hex_away_track)
		return 1;

doover:
	/* request an update of AWAY status of 1 channel every 30 seconds */
	full = TRUE;
	sent = 0;	/* number of WHOs (users) requested */
	list = sess_list;
	while (list)
	{
		sess = list->data;

		if (sess->server->connected &&
			 sess->type == SESS_CHANNEL &&
			 sess->channel[0] &&
			 (sess->total <= prefs.hex_away_size_max || !prefs.hex_away_size_max))
		{
			if (!sess->done_away_check)
			{
				full = FALSE;

				/* if we're under 31 WHOs, send another channels worth */
				if (sent < 31 && !sess->doing_who)
				{
					sess->done_away_check = TRUE;
					sess->doing_who = TRUE;
					/* this'll send a WHO #channel */
					sess->server->p_away_status (sess->server, sess->channel);
					sent += sess->total;
				}
			}
		}

		list = list->next;
	}

	/* done them all, reset done_away_check to FALSE and start over unless we have away-notify */
	if (full)
	{
		list = sess_list;
		while (list)
		{
			sess = list->data;
			if (!sess->server->have_awaynotify)
				sess->done_away_check = FALSE;
			list = list->next;
		}
		loop++;
		if (loop < 2)
			goto doover;
	}

	return 1;
}

/* these are only run if the lagometer is enabled */
static int
hexchat_lag_check (void)   /* this gets called every 30 seconds */
{
	lag_check ();
	return 1;
}

static int
hexchat_lag_check_update (void)   /* this gets called every 0.5 seconds */
{
	lagcheck_update ();
	return 1;
}

/* call whenever timeout intervals change */
void
hexchat_reinit_timers (void)
{
	static int lag_check_update_tag = 0;
	static int lag_check_tag = 0;
	static int away_tag = 0;

	/* notify timeout */
	if (prefs.hex_notify_timeout && notify_tag == 0)
	{
		notify_tag = fe_timeout_add_seconds (prefs.hex_notify_timeout,
						     notify_checklist, NULL);
	}
	else if (!prefs.hex_notify_timeout && notify_tag != 0)
	{
		fe_timeout_remove (notify_tag);
		notify_tag = 0;
	}

	/* away status tracking */
	if (prefs.hex_away_track && away_tag == 0)
	{
		away_tag = fe_timeout_add_seconds (prefs.hex_away_timeout, away_check, NULL);
	}
	else if (!prefs.hex_away_track && away_tag != 0)
	{
		fe_timeout_remove (away_tag);
		away_tag = 0;
	}

	/* lag-o-meter */
	if (prefs.hex_gui_lagometer && lag_check_update_tag == 0)
	{
		lag_check_update_tag = fe_timeout_add (500, hexchat_lag_check_update, NULL);
	}
	else if (!prefs.hex_gui_lagometer && lag_check_update_tag != 0)
	{
		fe_timeout_remove (lag_check_update_tag);
		lag_check_update_tag = 0;
	}

	/* network timeouts and lag-o-meter */
	if ((prefs.hex_net_ping_timeout != 0 || prefs.hex_gui_lagometer)
	    && lag_check_tag == 0)
	{
		lag_check_tag = fe_timeout_add_seconds (30, hexchat_lag_check, NULL);
	}
	else if ((!prefs.hex_net_ping_timeout && !prefs.hex_gui_lagometer)
					 && lag_check_tag != 0)
	{
		fe_timeout_remove (lag_check_tag);
		lag_check_tag = 0;
	}
}

/* executed when the first irc window opens */

static void
irc_init (session *sess)
{
	static int done_init = FALSE;
	char *buf;

	if (done_init)
		return;

	done_init = TRUE;

	plugin_add (sess, NULL, NULL, timer_plugin_init, NULL, NULL, FALSE);
	plugin_add (sess, NULL, NULL, identd_plugin_init, identd_plugin_deinit, NULL, FALSE);

#ifdef USE_PLUGIN
	if (!arg_skip_plugins)
		plugin_auto_load (sess);	/* autoload ~/.xchat *.so */
#endif

#ifdef USE_DBUS
	plugin_add (sess, NULL, NULL, dbus_plugin_init, NULL, NULL, FALSE);
#endif

	hexchat_reinit_timers ();

	if (arg_url != NULL)
	{
		buf = g_strdup_printf ("server %s", arg_url);
		g_free (arg_url);	/* from GOption */
		handle_command (sess, buf, FALSE);
		g_free (buf);
	}
	
	if (arg_urls != NULL)
	{
		guint i;
		for (i = 0; i < g_strv_length (arg_urls); i++)
		{
			buf = g_strdup_printf ("%s %s", i==0? "server" : "newserver", arg_urls[i]);
			handle_command (sess, buf, FALSE);
			g_free (buf);
		}
		g_strfreev (arg_urls);
	}

	if (arg_command != NULL)
	{
		handle_command (sess, arg_command, FALSE);
		g_free (arg_command);
	}

	/* load -e <xdir>/startup.txt */
	load_perform_file (sess, "startup.txt");
}

static session *
session_new (server *serv, char *from, int type, int focus)
{
	session *sess;

	sess = g_new0 (struct session, 1);

	sess->server = serv;
	sess->logfd = -1;
	sess->type = type;

	sess->alert_balloon = SET_DEFAULT;
	sess->alert_beep = SET_DEFAULT;
	sess->alert_taskbar = SET_DEFAULT;
	sess->alert_tray = SET_DEFAULT;

	sess->text_hidejoinpart = SET_DEFAULT;
	sess->text_logging = SET_DEFAULT;
	sess->text_scrollback = SET_DEFAULT;
	sess->text_strip = SET_DEFAULT;

	sess->lastact_idx = LACT_NONE;

	if (from != NULL)
	{
		safe_strcpy(sess->channel, from, CHANLEN);
		safe_strcpy(sess->session_name, from, CHANLEN);
	}

	sess_list = g_slist_prepend (sess_list, sess);

	fe_new_window (sess, focus);

	return sess;
}

session *
new_ircwindow (server *serv, char *name, int type, int focus)
{
	session *sess;

	switch (type)
	{
	case SESS_SERVER:
		serv = server_new ();
		if (prefs.hex_gui_tab_server)
			sess = session_new (serv, name, SESS_SERVER, focus);
		else
			sess = session_new (serv, name, SESS_CHANNEL, focus);
		serv->server_session = sess;
		serv->front_session = sess;
		break;
	case SESS_DIALOG:
		sess = session_new (serv, name, type, focus);
		break;
	default:
/*	case SESS_CHANNEL:
	case SESS_NOTICES:
	case SESS_SNOTICES:*/
		sess = session_new (serv, name, type, focus);
		break;
	}

	irc_init (sess);
	chanopt_load (sess);
	scrollback_load (sess);
	if (sess->scrollwritten && sess->scrollback_replay_marklast)
		sess->scrollback_replay_marklast (sess);
	if (type == SESS_DIALOG)
	{
		struct User *user;

		log_open_or_close (sess);

		user = userlist_find_global (serv, name);
		if (user && user->hostname)
			set_topic (sess, user->hostname, user->hostname);
	}
	plugin_emit_dummy_print (sess, "Open Context", -1);

	return sess;
}

static void
exec_notify_kill (session * sess)
{
#ifndef WIN32
	struct nbexec *re;
	if (sess->running_exec != NULL)
	{
		re = sess->running_exec;
		sess->running_exec = NULL;
		kill (re->childpid, SIGKILL);
		waitpid (re->childpid, NULL, WNOHANG);
		fe_input_remove (re->iotag);
		close (re->myfd);
		g_free (re->linebuf);
		g_free (re);
	}
#endif
}

static void
send_quit_or_part (session * killsess)
{
	int willquit = TRUE;
	GSList *list;
	session *sess;
	server *killserv = killsess->server;

	/* check if this is the last session using this server */
	list = sess_list;
	while (list)
	{
		sess = (session *) list->data;
		if (sess->server == killserv && sess != killsess)
		{
			willquit = FALSE;
			list = 0;
		} else
			list = list->next;
	}

	if (hexchat_is_quitting)
		willquit = TRUE;

	if (killserv->connected)
	{
		if (willquit)
		{
			if (!killserv->sent_quit)
			{
				killserv->flush_queue (killserv);
				server_sendquit (killsess);
				killserv->sent_quit = TRUE;
			}
		} else
		{
			if (killsess->type == SESS_CHANNEL && killsess->channel[0] &&
				 !killserv->sent_quit)
			{
				server_sendpart (killserv, killsess->channel, 0);
			}
		}
	}
}

void
session_free (session *killsess)
{
	server *killserv = killsess->server;
	session *sess;
	GSList *list;
	int oldidx;

	plugin_emit_dummy_print (killsess, "Close Context", 0);

	if (current_tab == killsess)
		current_tab = NULL;

	if (killserv->server_session == killsess)
		killserv->server_session = NULL;

	if (killserv->front_session == killsess)
	{
		/* front_session is closed, find a valid replacement */
		killserv->front_session = NULL;
		list = sess_list;
		while (list)
		{
			sess = (session *) list->data;
			if (sess != killsess && sess->server == killserv)
			{
				killserv->front_session = sess;
				if (!killserv->server_session)
					killserv->server_session = sess;
				break;
			}
			list = list->next;
		}
	}

	if (!killserv->server_session)
		killserv->server_session = killserv->front_session;

	sess_list = g_slist_remove (sess_list, killsess);

	if (killsess->type == SESS_CHANNEL)
		userlist_free (killsess);

	oldidx = killsess->lastact_idx;
	if (oldidx != LACT_NONE)
		sess_list_by_lastact[oldidx] = g_list_remove(sess_list_by_lastact[oldidx], killsess);

	exec_notify_kill (killsess);

	log_close (killsess);
	scrollback_close (killsess);
	chanopt_save (killsess);

	send_quit_or_part (killsess);

	history_free (&killsess->history);
	g_free (killsess->topic);
	g_free (killsess->current_modes);

	fe_session_callback (killsess);

	if (current_sess == killsess)
	{
		current_sess = NULL;
		if (sess_list)
			current_sess = sess_list->data;
	}

	g_free (killsess);

	if (!sess_list && !in_hexchat_exit)
		hexchat_exit ();						/* sess_list is empty, quit! */

	list = sess_list;
	while (list)
	{
		sess = (session *) list->data;
		if (sess->server == killserv)
			return;					  /* this server is still being used! */
		list = list->next;
	}

	server_free (killserv);
}

static void
free_sessions (void)
{
	GSList *list = sess_list;

	while (list)
	{
		fe_close_window (list->data);
		list = sess_list;
	}
}


static char defaultconf_ctcp[] =
	"NAME TIME\n"				"CMD nctcp %s TIME %t\n\n"\
	"NAME PING\n"				"CMD nctcp %s PING %d\n\n";

static char defaultconf_replace[] =
	"NAME teh\n"				"CMD the\n\n";
/*	"NAME r\n"					"CMD are\n\n"\
	"NAME u\n"					"CMD you\n\n"*/

static char defaultconf_commands[] =
	"NAME ACTION\n"		"CMD me &2\n\n"\
	"NAME AME\n"			"CMD allchan me &2\n\n"\
	"NAME ANICK\n"			"CMD allserv nick &2\n\n"\
	"NAME AMSG\n"			"CMD allchan say &2\n\n"\
	"NAME BANLIST\n"		"CMD quote MODE %c +b\n\n"\
	"NAME CHAT\n"			"CMD dcc chat %2\n\n"\
	"NAME DIALOG\n"		"CMD query %2\n\n"\
	"NAME DMSG\n"			"CMD msg =%2 &3\n\n"\
	"NAME EXIT\n"			"CMD quit\n\n"\
	"NAME GREP\n"			"CMD lastlog -r -- &2\n\n"\
	"NAME IGNALL\n"			"CMD ignore %2!*@* ALL\n\n"\
	"NAME J\n"				"CMD join &2\n\n"\
	"NAME KILL\n"			"CMD quote KILL %2 :&3\n\n"\
	"NAME LEAVE\n"			"CMD part &2\n\n"\
	"NAME M\n"				"CMD msg &2\n\n"\
	"NAME OMSG\n"			"CMD msg @%c &2\n\n"\
	"NAME ONOTICE\n"		"CMD notice @%c &2\n\n"\
	"NAME RAW\n"			"CMD quote &2\n\n"\
	"NAME SERVHELP\n"		"CMD quote HELP\n\n"\
	"NAME SPING\n"			"CMD ping\n\n"\
	"NAME SQUERY\n"		"CMD quote SQUERY %2 :&3\n\n"\
	"NAME SSLSERVER\n"	"CMD server -ssl &2\n\n"\
	"NAME SV\n"				"CMD echo HexChat %v %m\n\n"\
	"NAME UMODE\n"			"CMD mode %n &2\n\n"\
	"NAME UPTIME\n"		"CMD quote STATS u\n\n"\
	"NAME VER\n"			"CMD ctcp %2 VERSION\n\n"\
	"NAME VERSION\n"		"CMD ctcp %2 VERSION\n\n"\
	"NAME WALLOPS\n"		"CMD quote WALLOPS :&2\n\n"\
        "NAME WI\n"                     "CMD quote WHOIS %2\n\n"\
	"NAME WII\n"			"CMD quote WHOIS %2 %2\n\n";

static char defaultconf_urlhandlers[] =
		"NAME Open Link in a new Firefox Window\n"		"CMD !firefox -new-window %s\n\n";

#ifdef USE_SIGACTION
/* Close and open log files on SIGUSR1. Usefull for log rotating */

static void 
sigusr1_handler (int signal, siginfo_t *si, void *un)
{
	GSList *list = sess_list;
	session *sess;

	while (list)
	{
		sess = list->data;
		log_open_or_close (sess);
		list = list->next;
	}
}

/* Execute /SIGUSR2 when SIGUSR2 received */

static void
sigusr2_handler (int signal, siginfo_t *si, void *un)
{
	session *sess = current_sess;

	if (sess)
		handle_command (sess, "SIGUSR2", FALSE);
}
#endif

static gint
xchat_auto_connect (gpointer userdata)
{
	servlist_auto_connect (NULL);
	return 0;
}

static void
xchat_init (void)
{
	char buf[3068];

#ifdef WIN32
	WSADATA wsadata;

	if (WSAStartup(0x0202, &wsadata) != 0)
	{
		MessageBox (NULL, "Cannot find winsock 2.2+", "Error", MB_OK);
		exit (0);
	}
#endif	/* !WIN32 */

#ifdef USE_SIGACTION
	struct sigaction act;

	/* ignore SIGPIPE's */
	act.sa_handler = SIG_IGN;
	act.sa_flags = 0;
	sigemptyset (&act.sa_mask);
	sigaction (SIGPIPE, &act, NULL);

	/* Deal with SIGUSR1's & SIGUSR2's */
	act.sa_sigaction = sigusr1_handler;
	act.sa_flags = 0;
	sigemptyset (&act.sa_mask);
	sigaction (SIGUSR1, &act, NULL);

	act.sa_sigaction = sigusr2_handler;
	act.sa_flags = 0;
	sigemptyset (&act.sa_mask);
	sigaction (SIGUSR2, &act, NULL);
#else
#ifndef WIN32
	/* good enough for these old systems */
	signal (SIGPIPE, SIG_IGN);
#endif
#endif

	load_text_events ();
	sound_load ();
	notify_load ();
	ignore_load ();

	g_snprintf (buf, sizeof (buf),
		"NAME %s~%s~\n"				"CMD query %%s\n\n"\
		"NAME %s~%s~\n"				"CMD send %%s\n\n"\
		"NAME %s~%s~\n"				"CMD whois %%s %%s\n\n"\
		"NAME %s~%s~\n"				"CMD notify -n ASK %%s\n\n"\
		"NAME %s~%s~\n"				"CMD ignore %%s!*@* ALL\n\n"\

		"NAME SUB\n"					"CMD %s\n\n"\
			"NAME %s\n"					"CMD op %%a\n\n"\
			"NAME %s\n"					"CMD deop %%a\n\n"\
			"NAME SEP\n"				"CMD \n\n"\
			"NAME %s\n"					"CMD voice %%a\n\n"\
			"NAME %s\n"					"CMD devoice %%a\n"\
			"NAME SEP\n"				"CMD \n\n"\
			"NAME SUB\n"				"CMD %s\n\n"\
				"NAME %s\n"				"CMD kick %%s\n\n"\
				"NAME %s\n"				"CMD ban %%s\n\n"\
				"NAME SEP\n"			"CMD \n\n"\
				"NAME %s *!*@*.host\n""CMD ban %%s 0\n\n"\
				"NAME %s *!*@domain\n""CMD ban %%s 1\n\n"\
				"NAME %s *!*user@*.host\n""CMD ban %%s 2\n\n"\
				"NAME %s *!*user@domain\n""CMD ban %%s 3\n\n"\
				"NAME SEP\n"			"CMD \n\n"\
				"NAME %s *!*@*.host\n""CMD kickban %%s 0\n\n"\
				"NAME %s *!*@domain\n""CMD kickban %%s 1\n\n"\
				"NAME %s *!*user@*.host\n""CMD kickban %%s 2\n\n"\
				"NAME %s *!*user@domain\n""CMD kickban %%s 3\n\n"\
			"NAME ENDSUB\n"			"CMD \n\n"\
		"NAME ENDSUB\n"				"CMD \n\n",

		_("_Open Dialog Window"), "gtk-go-up",
		_("_Send a File" ELLIPSIS), "gtk-floppy",
		_("_User Info (WhoIs)"), "gtk-info",
		_("_Add to Friends List" ELLIPSIS), "gtk-add",
		_("_Ignore"), "gtk-stop",
		_("O_perator Actions"),

		_("Give Ops"),
		_("Take Ops"),
		_("Give Voice"),
		_("Take Voice"),

		_("Kick/Ban"),
		_("Kick"),
		_("Ban"),
		_("Ban"),
		_("Ban"),
		_("Ban"),
		_("Ban"),
		_("KickBan"),
		_("KickBan"),
		_("KickBan"),
		_("KickBan"));

	list_loadconf ("popup.conf", &popup_list, buf);

	g_snprintf (buf, sizeof (buf),
		"NAME %s\n"				"CMD part\n\n"
		"NAME %s\n"				"CMD getstr # join \"%s\"\n\n"
		"NAME %s\n"				"CMD quote LINKS\n\n"
		"NAME %s\n"				"CMD ping\n\n"
		"NAME TOGGLE %s\n"	"CMD irc_hide_version\n\n",
				_("Leave Channel"),
				_("Join Channel..."),
				_("Enter Channel to Join:"),
				_("Server Links"),
				_("Ping Server"),
				_("Hide Version"));
	list_loadconf ("usermenu.conf", &usermenu_list, buf);

	g_snprintf (buf, sizeof (buf),
		"NAME %s\n"		"CMD op %%a\n\n"
		"NAME %s\n"		"CMD deop %%a\n\n"
		"NAME %s\n"		"CMD ban %%s\n\n"
		"NAME %s\n"		"CMD getstr \"%s\" \"kick %%s\" \"%s\"\n\n"
		"NAME %s\n"		"CMD send %%s\n\n"
		"NAME %s\n"		"CMD query %%s\n\n",
				_("Op"),
				_("DeOp"),
				_("Ban"),
				_("Kick"),
				_("bye"),
				_("Enter reason to kick %s:"),
				_("Send File"),
				_("Dialog"));
	list_loadconf ("buttons.conf", &button_list, buf);

	g_snprintf (buf, sizeof (buf),
		"NAME %s\n"				"CMD whois %%s %%s\n\n"
		"NAME %s\n"				"CMD send %%s\n\n"
		"NAME %s\n"				"CMD dcc chat %%s\n\n"
		"NAME %s\n"				"CMD clear\n\n"
		"NAME %s\n"				"CMD ping %%s\n\n",
				_("WhoIs"),
				_("Send"),
				_("Chat"),
				_("Clear"),
				_("Ping"));
	list_loadconf ("dlgbuttons.conf", &dlgbutton_list, buf);

	list_loadconf ("tabmenu.conf", &tabmenu_list, NULL);
	list_loadconf ("ctcpreply.conf", &ctcp_list, defaultconf_ctcp);
	list_loadconf ("commands.conf", &command_list, defaultconf_commands);
	list_loadconf ("replace.conf", &replace_list, defaultconf_replace);
	list_loadconf ("urlhandlers.conf", &urlhandler_list,
						defaultconf_urlhandlers);

	servlist_init ();							/* load server list */

	/* if we got a URL, don't open the server list GUI */
	if (!prefs.hex_gui_slist_skip && !arg_url && !arg_urls)
		fe_serverlist_open (NULL);

	/* turned OFF via -a arg or by passing urls */
	if (!arg_dont_autoconnect && !arg_urls && !arg_url)
	{
		/* do any auto connects */
		if (!servlist_have_auto ())	/* if no new windows open .. */
		{
			/* and no serverlist gui ... */
			if (prefs.hex_gui_slist_skip || arg_url || arg_urls)
				/* we'll have to open one. */
				new_ircwindow (NULL, NULL, SESS_SERVER, 0);
		} else
		{
			fe_idle_add (xchat_auto_connect, NULL);
		}
	} else
	{
		if (prefs.hex_gui_slist_skip || arg_url || arg_urls)
			new_ircwindow (NULL, NULL, SESS_SERVER, 0);
	}
}

void
hexchat_exit (void)
{
	hexchat_is_quitting = TRUE;
	in_hexchat_exit = TRUE;
	plugin_kill_all ();
	fe_cleanup ();

	save_config ();
	if (prefs.save_pevents)
	{
		pevent_save (NULL);
	}

	sound_save ();
	notify_save ();
	ignore_save ();
	free_sessions ();
	chanopt_save_all (TRUE);
	servlist_cleanup ();
	fe_exit ();
}

void
hexchat_exec (const char *cmd)
{
	util_exec (cmd);
}


static void
set_locale (void)
{
#ifdef WIN32
	char hexchat_lang[13];	/* LC_ALL= plus 5 chars of hex_gui_lang and trailing \0 */

	strcpy (hexchat_lang, "LC_ALL=");

	if (0 <= prefs.hex_gui_lang && prefs.hex_gui_lang < LANGUAGES_LENGTH)
		strcat (hexchat_lang, languages[prefs.hex_gui_lang]);
	else
		strcat (hexchat_lang, "en");

	putenv (hexchat_lang);
#endif
}

int
main (int argc, char *argv[])
{
	int i;
	int ret;

#ifdef WIN32
	HRESULT coinit_result;
#endif

	srand ((unsigned int) time (NULL)); /* CL: do this only once! */

	/* We must check for the config dir parameter, otherwise load_config() will behave incorrectly.
	 * load_config() must come before fe_args() because fe_args() calls gtk_init() which needs to
	 * know the language which is set in the config. The code below is copy-pasted from fe_args()
	 * for the most part. */
	if (argc >= 2)
	{
		for (i = 1; i < argc; i++)
		{
			if ((strcmp (argv[i], "-d") == 0 || strcmp (argv[i], "--cfgdir") == 0)
				&& i + 1 < argc)
			{
				xdir = g_strdup (argv[i + 1]);
			}
			else if (strncmp (argv[i], "--cfgdir=", 9) == 0)
			{
				xdir = g_strdup (argv[i] + 9);
			}

			if (xdir != NULL)
			{
				if (xdir[strlen (xdir) - 1] == G_DIR_SEPARATOR)
				{
					xdir[strlen (xdir) - 1] = 0;
				}
				break;
			}
		}
	}

#if ! GLIB_CHECK_VERSION (2, 36, 0)
	g_type_init ();
#endif

	if (check_config_dir () == 0)
	{
		if (load_config () != 0)
			load_default_config ();
	} else
	{
		/* this is probably the first run */
		load_default_config ();
		make_config_dirs ();
		make_dcc_dirs ();
	}

	/* we MUST do this after load_config () AND before fe_init (thus gtk_init) otherwise it will fail */
	set_locale ();

	ret = fe_args (argc, argv);
	if (ret != -1)
		return ret;
	
#ifdef USE_DBUS
	hexchat_remote ();
#endif

#ifdef WIN32
	coinit_result = CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);
	if (SUCCEEDED (coinit_result))
	{
		CoInitializeSecurity (NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	}
#endif

	fe_init ();

	/* This is done here because cfgfiles.c is too early in
	* the startup process to use gtk functions. */
	if (g_access (get_xdir (), W_OK) != 0)
	{
		char buf[2048];

		g_snprintf (buf, sizeof(buf),
			_("You do not have write access to %s. Nothing from this session can be saved."),
			get_xdir ());
		fe_message (buf, FE_MSG_ERROR);
	}

#ifndef WIN32
#ifndef __EMX__
	/* OS/2 uses UID 0 all the time */
	if (getuid () == 0)
		fe_message (_("* Running IRC as root is stupid! You should\n"
			      "  create a User Account and use that to login.\n"), FE_MSG_WARN|FE_MSG_WAIT);
#endif
#endif /* !WIN32 */

	xchat_init ();

	fe_main ();

#ifdef WIN32
	if (SUCCEEDED (coinit_result))
	{
		CoUninitialize ();
	}
#endif

#ifdef WIN32
	WSACleanup ();
#endif

	return 0;
}
