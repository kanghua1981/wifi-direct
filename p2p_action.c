
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>


struct wpa_ctrl {
	int s;
	struct sockaddr_un local;
	struct sockaddr_un dest;
};

struct os_time {
        long sec;
        long usec;
};


/** A P2P device requested GO negotiation, but we were not ready to start the
 * negotiation */
#define P2P_EVENT_GO_NEG_REQUEST "P2P-GO-NEG-REQUEST "
#define P2P_EVENT_GO_NEG_SUCCESS "P2P-GO-NEG-SUCCESS "
#define P2P_EVENT_GO_NEG_FAILURE "P2P-GO-NEG-FAILURE "
#define P2P_EVENT_GROUP_FORMATION_SUCCESS "P2P-GROUP-FORMATION-SUCCESS "
#define P2P_EVENT_GROUP_FORMATION_FAILURE "P2P-GROUP-FORMATION-FAILURE "
#define P2P_EVENT_GROUP_STARTED "P2P-GROUP-STARTED "
#define P2P_EVENT_GROUP_REMOVED "P2P-GROUP-REMOVED "
#define P2P_EVENT_CROSS_CONNECT_ENABLE "P2P-CROSS-CONNECT-ENABLE "
#define P2P_EVENT_CROSS_CONNECT_DISABLE "P2P-CROSS-CONNECT-DISABLE "
/* parameters: <peer address> <PIN> */
#define P2P_EVENT_PROV_DISC_SHOW_PIN "P2P-PROV-DISC-SHOW-PIN "
/* parameters: <peer address> */
#define P2P_EVENT_PROV_DISC_ENTER_PIN "P2P-PROV-DISC-ENTER-PIN "
/* parameters: <peer address> */
#define P2P_EVENT_PROV_DISC_PBC_REQ "P2P-PROV-DISC-PBC-REQ "
/* parameters: <peer address> */
#define P2P_EVENT_PROV_DISC_PBC_RESP "P2P-PROV-DISC-PBC-RESP "
/* parameters: <peer address> <status> */
#define P2P_EVENT_PROV_DISC_FAILURE "P2P-PROV-DISC-FAILURE"
/* parameters: <freq> <src addr> <dialog token> <update indicator> <TLVs> */
#define P2P_EVENT_SERV_DISC_REQ "P2P-SERV-DISC-REQ "
/* parameters: <src addr> <update indicator> <TLVs> */
#define P2P_EVENT_SERV_DISC_RESP "P2P-SERV-DISC-RESP "
#define P2P_EVENT_INVITATION_RECEIVED "P2P-INVITATION-RECEIVED "
#define P2P_EVENT_INVITATION_RESULT "P2P-INVITATION-RESULT "
#define P2P_EVENT_FIND_STOPPED "P2P-FIND-STOPPED "



#define P2P_REQUEST_STATUS   0
#define P2P_STARTED_STATUS   1
#define P2P_REMOVED_STATUS   2
#define P2P_CROSS_CONNECT_ENABLE_STATUS   3
#define P2P_CROSS_CONNECT_DISABLE_STATUS  4
#define P2P_INVITATION_STATUS    5
#define P2P_LISTEN_STATUS  0x6
int p2p_status = P2P_LISTEN_STATUS;


static struct wpa_ctrl *ctrl_conn;
static int wpa_cli_quit = 0;
static int wpa_cli_attached = 0;
//static int wpa_cli_connected = 0;
//static int wpa_cli_last_id = 0;
#define CONFIG_CTRL_IFACE_DIR "/var/run/wpa_supplicant"
static const char *ctrl_iface_dir = CONFIG_CTRL_IFACE_DIR;
static char *ctrl_ifname = NULL;
//static const char *pid_file = NULL;
static const char *action_file = NULL;
static int ping_interval = 10;

static char *localip = NULL;
static void wpa_cli_action_process(const char *msg);

int wpa_ctrl_get_fd(struct wpa_ctrl *ctrl)
{
	return ctrl->s;
}

#ifndef CONFIG_CTRL_IFACE_CLIENT_DIR
#define CONFIG_CTRL_IFACE_CLIENT_DIR "/tmp"
#endif /* CONFIG_CTRL_IFACE_CLIENT_DIR */
#ifndef CONFIG_CTRL_IFACE_CLIENT_PREFIX
#define CONFIG_CTRL_IFACE_CLIENT_PREFIX "wpa_ctrl_"
#endif /* CONFIG_CTRL_IFACE_CLIENT_PREFIX */
size_t strlcpy(char *dest, const char *src, size_t siz)
{
        const char *s = src;
        size_t left = siz;

        if (left) {
                /* Copy string up to the maximum size of the dest buffer */
                while (--left != 0) {
                        if ((*dest++ = *s++) == '\0')
                                break;
                }
        }

        if (left == 0) {
                /* Not enough room for the string; force NUL-termination */
                if (siz != 0)
                        *dest = '\0';
                while (*s++)
                        ; /* determine total src string length */
        }

        return s - src - 1;
}

struct wpa_ctrl * wpa_ctrl_open(const char *ctrl_path)
{
	struct wpa_ctrl *ctrl;
	static int counter = 0;
	int ret;
	size_t res;
	int tries = 0;
	int flags;

	ctrl = malloc(sizeof(*ctrl));
	if (ctrl == NULL)
		return NULL;
	memset(ctrl, 0, sizeof(*ctrl));

	ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
		free(ctrl);
		perror("open socket error\n");
		return NULL;
	}

	ctrl->local.sun_family = AF_UNIX;
	counter++;
try_again:
	ret = snprintf(ctrl->local.sun_path, sizeof(ctrl->local.sun_path),
			  CONFIG_CTRL_IFACE_CLIENT_DIR "/"
			  CONFIG_CTRL_IFACE_CLIENT_PREFIX "%d-%d",
			  (int) getpid(), counter);
	if (ret < 0 || (size_t) ret >= sizeof(ctrl->local.sun_path)) {
		close(ctrl->s);
		free(ctrl);
		printf("snprintf error\n");
		return NULL;
	}
	tries++;
	if (bind(ctrl->s, (struct sockaddr *) &ctrl->local,
		    sizeof(ctrl->local)) < 0) {
		if (errno == EADDRINUSE && tries < 2) {
			/*
			 * getpid() returns unique identifier for this instance
			 * of wpa_ctrl, so the existing socket file must have
			 * been left by unclean termination of an earlier run.
			 * Remove the file and try again.
			 */
			unlink(ctrl->local.sun_path);
			
			goto try_again;
		}
		close(ctrl->s);
		free(ctrl);
		printf("bind error\n");
		return NULL;
	}
	ctrl->dest.sun_family = AF_UNIX;
	res = strlcpy(ctrl->dest.sun_path, ctrl_path,sizeof(ctrl->dest.sun_path));
	if (res > sizeof(ctrl->dest.sun_path)) {
		close(ctrl->s);
		free(ctrl);
		return NULL;
	}
	if (connect(ctrl->s, (struct sockaddr *) &ctrl->dest,
		    sizeof(ctrl->dest)) < 0) {
		close(ctrl->s);
		unlink(ctrl->local.sun_path);
		free(ctrl);
		printf("connect wpa_suppliant error\n");
		return NULL;
	}

	/*
	 * Make socket non-blocking so that we don't hang forever if
	 * target dies unexpectedly.
	 */
	flags = fcntl(ctrl->s, F_GETFL);
	if (flags >= 0) {
		flags |= O_NONBLOCK;
		if (fcntl(ctrl->s, F_SETFL, flags) < 0) {
			perror("fcntl(ctrl->s, O_NONBLOCK)");
			/* Not fatal, continue on.*/
		}
	}

	return ctrl;
}

void wpa_ctrl_close(struct wpa_ctrl *ctrl)
{
	if (ctrl == NULL)
		return;
	unlink(ctrl->local.sun_path);
	if (ctrl->s >= 0)
		close(ctrl->s);
	free(ctrl);
}
int get_time(struct os_time *t)
{
        int res;
        struct timeval tv;
        res = gettimeofday(&tv, NULL);
        t->sec = tv.tv_sec;
        t->usec = tv.tv_usec;
        return res;
}

static int wpa_cli_open_connection(const char *ifname)
{

	char *cfile = NULL;
	int flen, res;

	if (ifname == NULL)
		return -1;

	if (cfile == NULL) {
		flen = strlen(ctrl_iface_dir) + strlen(ifname) + 2;
		cfile = malloc(flen);
		if (cfile == NULL)
			return -1;
		res = snprintf(cfile, flen, "%s/%s", ctrl_iface_dir,
				  ifname);
		if (res < 0 || res >= flen) {
			free(cfile);
			return -1;
		}
	}

	ctrl_conn = wpa_ctrl_open(cfile);
	if (ctrl_conn == NULL) {
		free(cfile);
		return -1;
	}

	return 0;
}


int wpa_ctrl_request(struct wpa_ctrl *ctrl, const char *cmd, size_t cmd_len,
		     char *reply, size_t *reply_len,
		     void (*msg_cb)(char *msg, size_t len),void (*all_cb)(char *msg))
{
	struct timeval tv;
	struct os_time started_at;
	int res;
	fd_set rfds;
	const char *_cmd;
	char *cmd_buf = NULL;
	size_t _cmd_len;

	{
		_cmd = cmd;
		_cmd_len = cmd_len;
	}

	errno = 0;
	started_at.sec = 0;
	started_at.usec = 0;
retry_send:
	if (send(ctrl->s, _cmd, _cmd_len, 0) < 0) {
		if (errno == EAGAIN || errno == EBUSY || errno == EWOULDBLOCK)
		{
			/*
			 * Must be a non-blocking socket... Try for a bit
			 * longer before giving up.
			 */
			if (started_at.sec == 0)
				get_time(&started_at);
			else {
				struct os_time n;
				get_time(&n);
				/* Try for a few seconds. */
				if (n.sec > started_at.sec + 5)
					goto send_err;
			}
			sleep(1);
			goto retry_send;
		}
	send_err:
		free(cmd_buf);
		return -1;
	}
	free(cmd_buf);

	for (;;) {
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(ctrl->s, &rfds);
		res = select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
		if (res < 0)
			return res;
		if (FD_ISSET(ctrl->s, &rfds)) {
			res = recv(ctrl->s, reply, *reply_len, 0);
			if (res < 0)
				return res;
			if (res > 0 && reply[0] == '<') {
				/* This is an unsolicited message from
				 * wpa_supplicant, not the reply to the
				 * request. Use msg_cb to report this to the
				 * caller. */
				if (msg_cb) {
					/* Make sure the message is nul
					 * terminated. */
					if ((size_t) res == *reply_len)
						res = (*reply_len) - 1;
					reply[res] = '\0';
					msg_cb(reply, res);
				}
				continue;
			}
			if (all_cb) {
					all_cb(reply);
			}
			*reply_len = res;
			break;
		} else {
			return -2;
		}
	}
	return 0;
}

static int wpa_ctrl_attach_helper(struct wpa_ctrl *ctrl, int attach)
{
	char buf[10];
	int ret;
	size_t len = 10;

	ret = wpa_ctrl_request(ctrl, attach ? "ATTACH" : "DETACH", 6,
			       buf, &len, NULL,NULL);
	if (ret < 0)
		return ret;
	if (len == 3 && memcmp(buf, "OK\n", 3) == 0)
		return 0;
	return -1;
}

int wpa_ctrl_attach(struct wpa_ctrl *ctrl)
{
	return wpa_ctrl_attach_helper(ctrl, 1);
}


int wpa_ctrl_detach(struct wpa_ctrl *ctrl)
{
	return wpa_ctrl_attach_helper(ctrl, 0);
}


static void wpa_cli_close_connection(void)
{
	if (ctrl_conn == NULL)
		return;

	if (wpa_cli_attached) {
		wpa_ctrl_detach(ctrl_conn);
		wpa_cli_attached = 0;
	}
	wpa_ctrl_close(ctrl_conn);
	ctrl_conn = NULL;
	
}

static void wpa_cli_reconnect(void)
{
	wpa_cli_close_connection();
	if (wpa_cli_open_connection(ctrl_ifname) < 0)
		return;

}


int wpa_ctrl_recv(struct wpa_ctrl *ctrl, char *reply, size_t *reply_len)
{
	int res;

	res = recv(ctrl->s, reply, *reply_len, 0);
	if (res < 0)
		return res;
	*reply_len = res;
	return 0;
}

int wpa_ctrl_pending(struct wpa_ctrl *ctrl)
{
	struct timeval tv;
	fd_set rfds;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(ctrl->s, &rfds);
	select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
	return FD_ISSET(ctrl->s, &rfds);
}


static void wpa_cli_recv_pending(struct wpa_ctrl *ctrl, int action_monitor)
{
	if (ctrl_conn == NULL) {
		wpa_cli_reconnect();
		return;
	}
	while (wpa_ctrl_pending(ctrl) > 0) {
		char buf[256];
		size_t len = sizeof(buf) - 1;
		if (wpa_ctrl_recv(ctrl, buf, &len) == 0) {
			buf[len] = '\0';
			if (action_monitor)
				wpa_cli_action_process(buf);
		} else {
			printf("Could not read pending message.\n");
			break;
		}
	}

	if (wpa_ctrl_pending(ctrl) < 0) {
		printf("Connection to wpa_supplicant lost - trying to "
		       "reconnect\n");
		wpa_cli_reconnect();
	}
}




static int write_cmd(char *buf, size_t buflen, const char *cmd, int argc,
		     char *argv[])
{
	int i, res;
	char *pos, *end;

	pos = buf;
	end = buf + buflen;

	res = snprintf(pos, end - pos, "%s", cmd);
	if (res < 0 || res >= end - pos)
		goto fail;
	pos += res;

	for (i = 0; i < argc; i++) {
		res = snprintf(pos, end - pos, " %s", argv[i]);
		if (res < 0 || res >= end - pos)
			goto fail;
		pos += res;
	}

	buf[buflen - 1] = '\0';
	return 0;

fail:
	printf("Too long command\n");
	return -1;
}

static void wpa_cli_msg_cb(char *msg, size_t len)
{
	//printf("%s\n", msg);
}

static int _wpa_ctrl_command(struct wpa_ctrl *ctrl, char *cmd, int print)
{
	char buf[2048];
	size_t len;
	int ret;

	if (ctrl_conn == NULL) {
		printf("Not connected to wpa_supplicant - command dropped.\n");
		return -1;
	}
	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len,
			       wpa_cli_msg_cb,NULL);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}
	if (print) {
		buf[len] = '\0';
		printf("%s", buf);

	}
	return 0;
}


static int wpa_ctrl_command(struct wpa_ctrl *ctrl, char *cmd)
{
	return _wpa_ctrl_command(ctrl, cmd, 1);
}


static int wpa_cli_cmd(struct wpa_ctrl *ctrl, const char *cmd, int min_args,
		       int argc, char *argv[])
{
	char buf[256];
	if (argc < min_args) {
		printf("Invalid %s command - at least %d argument%s "
		       "required.\n", cmd, min_args,
		       min_args > 1 ? "s are" : " is");
		return -1;
	}
	if (write_cmd(buf, sizeof(buf), cmd, argc, argv) < 0)
		return -1;
	return wpa_ctrl_command(ctrl, buf);
}
static int str_match(const char *a, const char *b)
{
	return strncmp(a, b, strlen(b)) == 0;
}

static int handle_p2p_connect(char *pos)
{
    char desmac[32] = {0};
    //char argv[3][32];
    char buffers[128] = {0};
    //bzero(argv,3*32);
    printf("handle_p2p_connect=%s\n",pos);
    sscanf(pos,"%*s %s %*[^\n]",desmac);
    //sprintf(buffers,"P2P_CONNECT %s pbc go_intent=0",desmac);
    sprintf(buffers,"P2P_CONNECT %s pbc go_intent=0",desmac);
    //sprintf(buffers,"P2P_CONNECT %s pbc",desmac);
    //p2p_invite [persistent=<network id>|group=<group ifname>] [peer=address]
	//[go_dev_addr=address]
	//sprintf(buffers,"P2P_INVITE persistent=0 peer=%s",desmac);
    //strcpy((char*)argv[0],desmac);
    //strcpy((char*)argv[1],"pbc");
    //strcpy((char*)argv[2],"go_intent=0");
    //wpa_cli_cmd(ctrl_conn, "P2P_CONNECT", 2, 3, argv);
    wpa_ctrl_command(ctrl_conn,buffers);
    return 0 ;
}

static int handle_p2p_invitation(char *pos)
{
    char desmac[32] = {0};
    //char argv[3][32];
    char buffers[128] = {0};
    //bzero(argv,3*32);
    //wpa_ctrl_command(ctrl_conn,"P2P_GROUP_ADD");
    sscanf(pos,"%*s sa=%s %*[^\n]",desmac);
    //sprintf(buffers,"P2P_CONNECT %s pbc join go_intent=0",desmac);
    sprintf(buffers,"P2P_CONNECT %s pbc join",desmac);
    //sprintf(buffers,"P2P_REJECT %s",desmac);
    //strcpy((char*)argv[0],desmac);
    //strcpy((char*)argv[1],"pbc");
    //strcpy((char*)argv[2],"go_intent=0");
    //wpa_cli_cmd(ctrl_conn, "P2P_CONNECT", 2, 3, argv);
    wpa_ctrl_command(ctrl_conn,buffers);
    //wpa_ctrl_command(ctrl_conn,"P2P_CANCEL");
    //p2p_group_add
    return 0 ;
}

static int handle_p2p_start(char *pos)
{
    char ifname[32] = {0};
    char master[12] = {0};
    char cmd[128] = {0};
    sscanf(pos,"%*s %s %s %*[^\n]",ifname,master);

    //printf("handle_p2p_start=%s\n",pos);
    if (strncmp(master,"GO",2) == 0)
    {
        sprintf(cmd,"killall dnsmasq");
        system(cmd);
        bzero(cmd,128);
        sprintf(cmd,"ifconfig %s 192.168.42.1 up",ifname);
        system(cmd);

        bzero(cmd,128);
        sleep(1);
        //dnsmasq -x /var/run/dnsmasq.pid-kkk -i eth2 -F192.168.42.11,192.168.42.99 --listen-address 192.168.42.1 --dhcp-leasefile=/var/run/p2p-lease.lease -z
        sprintf(cmd,"dnsmasq -x /var/run/dnsmasq.pid-%s -i %s -F192.168.42.11,192.168.42.99"
                " --listen-address 192.168.42.1 --dhcp-leasefile=/var/run/p2p-lease.lease",
                ifname,ifname);
        
        system(cmd);
    }
    else if (strncmp(master,"client",6) == 0)
    {
		if (localip == NULL)
		{
			//sprintf(cmd,"udhcpc -p /var/run/udhcpc-%s.pid -s /lib/netifd/dhcp.script -f -t 0 -i %s -C &",ifname,ifname);
			sprintf(cmd,"ifconfig %s 192.168.42.49",ifname);
			//ubus call  network.interface.wifi_p2p add_device "{\"name\":\"eth0\"}"
			
			//sprintf(cmd,"ubus call  network.interface.wifi_p2p add_device \"{\\\"name\\\":\\\"%s\\\"}\"",ifname);
            //printf("%s\n",cmd);
		}
		else
		{
			sprintf(cmd,"ifconfig %s %s",ifname,localip);
		}
        system(cmd);
    }

    //system("echo 0 > /sys/class/leds/ap121:green:wifidirect/brightness");
}

static int handle_p2p_stop(char *pos)
{
#if 1
    char ifname[32] = {0};
    char master[12] = {0};
    char cmd[128] = {0};
    char buffers[64]={0};
    printf("handle_p2p_stop\n");
    sscanf(pos,"%*s %s %s %*[^\n]",ifname,master);
    sprintf(buffers,"P2P_GROUP_REMOVE %s",ifname);
    wpa_ctrl_command(ctrl_conn,buffers);
    
    //printf("handle_p2p_stop\n");
    
    if (strncmp(master,"GO",2) == 0)
    {
        sprintf(cmd,"killall udhcpd /var/run/udhcpd-%s.pid",ifname);
        system(cmd);
        bzero(cmd,128);
        sprintf(cmd,"ifconfig %s 0.0.0.0",ifname);
        system(cmd);
    }
    else if (strncmp(master,"client",6) == 0)
    {
        sprintf(cmd,"killall udhcpc",ifname);
        system(cmd);
        bzero(cmd,128);
        //sprintf(cmd,"ifconfig %s 0.0.0.0",ifname);
        //sprintf(cmd,"ubus call network.interface.wifi_p2p remove_device \"{\\\"name\\\":\\\"%s\\\"}\"",ifname);
        //printf("%s\n",cmd);
        //system(cmd);
        sprintf(cmd,"ifconfig %s down",ifname);
        //sprintf(cmd,"ubus call network.interface.wifi_p2p remove_device \"{\\\"name\\\":\\\"%s\\\"}\"",ifname);
        //printf("%s\n",cmd);
        system(cmd);
        //system("ubus call network.interface.wifi_p2p remove_device \"{\\\"name\\\":\\\"%s\\\"}\"",ifname);
    }

    //system("echo 1 > /sys/class/leds/ap121:green:wifidirect/brightness");
 #endif
}


static int handle_p2p_listen()
{
    //wpa_ctrl_command(ctrl_conn,"P2P_FIND");
    wpa_ctrl_command(ctrl_conn,"P2P_LISTEN");
}
time_t g_new_times = 0;
time_t g_old_times = 0;
#define P2P_TIME_OVER       30

static int checkp2pconnect(void)
{
    FILE *pp = NULL;
    char buffer[32] = {0};
    pp = popen("iw dev p2p-wlan0-0 station dump","r");
    if (pp == NULL)
    {
        return -1;
    }
    fgets(buffer,32,pp);
    if (strlen(buffer) == 0)
    {
        pclose(pp);
        return -1;
    }
    pclose(pp);
    return 0;
}

static int p2p_state_machine(const char *pos)
{
    
    int timedlt = 0;
  
    if (str_match(pos, P2P_EVENT_PROV_DISC_PBC_REQ)) {
		//p2p_status = P2P_STARTED_STATUS;
		//handle_p2p_start(pos);
        //wpa_ctrl_command(ctrl_conn,"p2p_find");
        system("wpa_cli -i p2p-wlan0-0 wps_pbc");
        //wpa_ctrl_command(ctrl_conn,"WPS_PBC");  
	}
   
	return 0;

}
#if 0

static int p2p_state_machine(const char *pos)
{
    
    int timedlt = 0;


    if (p2p_status == P2P_LISTEN_STATUS && str_match(pos, P2P_EVENT_GO_NEG_REQUEST)) {
        p2p_status = P2P_REQUEST_STATUS;
		//wpa_cli_cmd(ctrl_conn, "P2P_CONNECT", 2, 3, "XXX pbc go_intent=0");
		//wpa_ctrl_command(ctrl_conn,"P2P_GROUP_ADD persistent");
		handle_p2p_connect(pos);
		time(&g_old_times);
    }
    else if (p2p_status == P2P_LISTEN_STATUS && str_match(pos, P2P_EVENT_INVITATION_RECEIVED)) {
		p2p_status = P2P_INVITATION_STATUS;
		handle_p2p_invitation(pos);
		time(&g_old_times);
	}
	#if 0
	else if (/*p2p_status == P2P_STARTED_STATUS && */ str_match(pos, P2P_EVENT_PROV_DISC_PBC_REQ))
	{
	    //p2p_status = P2P_REQUEST_STATUS;
	    
        handle_p2p_connect(pos);
        time(&g_old_times);
	}
	#endif
    else if ((p2p_status == P2P_REQUEST_STATUS 
    || p2p_status == P2P_INVITATION_STATUS
    || p2p_status == P2P_LISTEN_STATUS)
    && str_match(pos, P2P_EVENT_GROUP_STARTED)) {
		p2p_status = P2P_STARTED_STATUS;
		handle_p2p_start(pos);
	} else if (p2p_status == P2P_STARTED_STATUS && str_match(pos, P2P_EVENT_GROUP_REMOVED)) {
        p2p_status = P2P_LISTEN_STATUS;
        handle_p2p_stop(pos);
	}
	else if (str_match(pos, "P2P-DEVICE-LOST"))
	{
	    p2p_status = P2P_LISTEN_STATUS;
        wpa_ctrl_command(ctrl_conn,"P2P_CANCEL");
	}
	
	if (p2p_status == P2P_REQUEST_STATUS || p2p_status == P2P_INVITATION_STATUS)
    {
        time(&g_new_times);
        timedlt = g_new_times - g_old_times;
        if (timedlt > P2P_TIME_OVER)
        {
            p2p_status = P2P_LISTEN_STATUS;
        }
    }
#if 0
	else if (str_match(pos, P2P_EVENT_CROSS_CONNECT_ENABLE)) {
		handle_p2p_connect(pos);
	} else if (str_match(pos, P2P_EVENT_CROSS_CONNECT_DISABLE)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, P2P_EVENT_GO_NEG_FAILURE)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, WPA_EVENT_TERMINATING)) {
		printf("wpa_supplicant is terminating - stop monitoring\n");
		wpa_cli_quit = 1;
	}
#endif
            
    
    g_old_times = g_new_times;
	return 0;

}

static int p2p_state_machine(const char *pos)
{
    
    int timedlt = 0;


    if (str_match(pos, P2P_EVENT_GO_NEG_REQUEST)) {
        p2p_status = P2P_REQUEST_STATUS;
		//wpa_cli_cmd(ctrl_conn, "P2P_CONNECT", 2, 3, "XXX pbc go_intent=0");
		//wpa_ctrl_command(ctrl_conn,"P2P_GROUP_ADD persistent");
		handle_p2p_connect(pos);
		time(&g_old_times);
    }
    else if (str_match(pos, P2P_EVENT_INVITATION_RECEIVED)) {
		p2p_status = P2P_INVITATION_STATUS;
		handle_p2p_invitation(pos);
		time(&g_old_times);
	}
	#if 1
	else if (str_match(pos, P2P_EVENT_PROV_DISC_PBC_REQ))
	{
	    p2p_status = P2P_INVITATION_STATUS;
        handle_p2p_connect(pos);
        //wpa_ctrl_command(ctrl_conn,P2P_EVENT_PROV_DISC_PBC_REQ);
        
        time(&g_old_times);
	}
	#endif
    else if ((p2p_status == P2P_REQUEST_STATUS 
    || p2p_status == P2P_INVITATION_STATUS
    || p2p_status == P2P_LISTEN_STATUS)
    && str_match(pos, P2P_EVENT_GROUP_STARTED)) {
		p2p_status = P2P_STARTED_STATUS;
		handle_p2p_start(pos);
	} else if (p2p_status == P2P_STARTED_STATUS && str_match(pos, P2P_EVENT_GROUP_REMOVED)) {
        p2p_status = P2P_LISTEN_STATUS;
        handle_p2p_stop(pos);
	}
	else if (str_match(pos, "P2P-DEVICE-LOST"))
	{
	    p2p_status = P2P_LISTEN_STATUS;
        wpa_ctrl_command(ctrl_conn,"P2P_CANCEL");
	}
	
	if (p2p_status == P2P_REQUEST_STATUS || p2p_status == P2P_INVITATION_STATUS)
    {
        time(&g_new_times);
        timedlt = g_new_times - g_old_times;
        if (timedlt > P2P_TIME_OVER)
        {
            p2p_status = P2P_LISTEN_STATUS;
        }
    }
#if 0
	else if (str_match(pos, P2P_EVENT_CROSS_CONNECT_ENABLE)) {
		handle_p2p_connect(pos);
	} else if (str_match(pos, P2P_EVENT_CROSS_CONNECT_DISABLE)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, P2P_EVENT_GO_NEG_FAILURE)) {
		wpa_cli_exec(action_file, ctrl_ifname, pos);
	} else if (str_match(pos, WPA_EVENT_TERMINATING)) {
		printf("wpa_supplicant is terminating - stop monitoring\n");
		wpa_cli_quit = 1;
	}
#endif
            
    
    g_old_times = g_new_times;
	return 0;

}

#endif

static void wpa_cli_action_process(const char *msg)
{
	const char *pos;
	char *copy = NULL, *id, *pos2;
   
    printf("%s\n",msg);
	pos = msg;
	if (*pos == '<') {
		/* skip priority */
		pos = strchr(pos, '>');
		if (pos)
			pos++;
		else
			pos = msg;
	}

	p2p_state_machine(pos);
	
}

static void wpa_cli_action_cb(char *msg, size_t len)
{
	wpa_cli_action_process(msg);
}

static void p2p_status_cb(char *msg)
{
	//if (p2p_status == P2P_LISTEN_STATUS)
    //{
    //    wpa_ctrl_command(ctrl_conn,"P2P_CANCEL");
    //    handle_p2p_listen();
    
    //}
    //printf("p2p_status_cb:%s\n",msg);
    //if (p2p_status == P2P_LISTEN_STATUS)
    //wpa_ctrl_command(ctrl_conn,"p2p_find");
    //system("wpa_cli -i p2p-wlan0-0 wps_pbc");
}

static void wpa_cli_action(struct wpa_ctrl *ctrl)
{

	fd_set rfds;
	int fd, res;
	struct timeval tv;
	char buf[256]; /* note: large enough to fit in unsolicited messages */
	size_t len;

	fd = wpa_ctrl_get_fd(ctrl);

	while (!wpa_cli_quit) {
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		tv.tv_sec = ping_interval;
		tv.tv_usec = 0;
		res = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (res < 0 && errno != EINTR) {
			perror("select");
			break;
		}
        
		if (FD_ISSET(fd, &rfds))
			wpa_cli_recv_pending(ctrl, 1);
		else {
			/* verify that connection is still working */
			len = sizeof(buf) - 1;
			if (wpa_ctrl_request(ctrl, "PING", 4, buf, &len,
					     wpa_cli_action_cb,p2p_status_cb) < 0 ||
			    len < 4 || memcmp(buf, "PONG", 4) != 0) {
				printf("wpa_supplicant did not reply to PING "
				       "command - exiting\n");
				continue;
			}
		}
	}
}

int main(int argc,char **argv)
{
    int ret  = 0;
    char cmd[256] = {0};
    if (argc < 2)
        return 0;

    ctrl_ifname = argv[1];
    localip = argv[2];
	/*
    if (localip == NULL)
    {
        localip = "192.168.49.42";
    }
	*/

    if (wpa_cli_open_connection(ctrl_ifname) != 0)
    {
        printf("open connection error\n");
        return -1;
    }
    if (wpa_ctrl_attach(ctrl_conn) == 0) {
				wpa_cli_attached = 1;
	} else {
		printf("Warning: Failed to attach to "
		       "wpa_supplicant.\n");
		return -1;
	}
    //p2p_status = P2P_LISTEN_STATUS;
    wpa_ctrl_command(ctrl_conn,"P2P_SET discoverability 1");
    
    wpa_ctrl_command(ctrl_conn,"P2P_SET managed 0");
    
   // wpa_ctrl_command(ctrl_conn,"P2P_EXT_LISTEN 10 5000");
    
    wpa_ctrl_command(ctrl_conn,"P2P_GROUP_ADD persistent=0");

    system("ifconfig p2p-wlan0-0 192.168.222.254 up");
    
    system("killall dnsmasq");
    
    sprintf(cmd,"dnsmasq -C /etc/dnsmasqp2p.conf");
    system(cmd);
#if 1
    wpa_cli_action(ctrl_conn);
#else
    while (1)
    {
        sleep(10);
        
        system("wpa_cli -i p2p-wlan0-0 wps_pbc");
    }
#endif
    return 0;

}
